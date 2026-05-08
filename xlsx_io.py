# -*- coding: utf-8 -*-
"""
최소 .xlsx 리더/라이터 — Python 표준 라이브러리만 사용 (zipfile + xml.etree).

핵심 의도:
  Excel 의 CSV 임포트는 셀 값이 '=', '-', '+', '@' 로 시작하면 수식으로 해석합니다.
  그래서 `-Pn`, `--version-all` 같은 nmap 옵션이 `#NAME?` 가 되거나 자동으로 `'`
  접두가 붙거나 손상됩니다.

  네이티브 xlsx 의 **shared string** 셀 (`<c t="s"><v>3</v></c>` + sharedStrings.xml
  엔트리) 은 Excel 이 절대 수식으로 해석하지 않습니다. 이 파일은 모든 데이터 셀을
  shared string 으로 작성합니다 (Excel 자체 저장 형식과 동일).

스키마:
  - 시트 1개 ("Sheet1")
  - 1행 = 헤더 (style 1, 굵게)
  - 그 외 모든 셀 = 일반 (style 0)
  - 모든 데이터 셀 type = "s" (shared string)
"""

import os
import re
import zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape


# XML 1.0 spec 에서 invalid control char (write 시 전부 제거).
# NSE 출력 등에 가끔 \x00, \x01, \x07 같은 것 들어와서 read 시 ParseError 유발.
# 허용: \t (\x09), \n (\x0a), \r (\x0d). 그 외 \x00-\x08, \x0b, \x0c, \x0e-\x1f 모두 제거.
_XML_INVALID_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# read_xlsx 보호 한계치. 정상 OOXML xlsx 파트는 한 개당 수 MB 미만,
# 합쳐도 수십 MB 를 넘지 않음. 악의적 zip-bomb / 비정상 파일 거부용.
_MAX_XLSX_PART_BYTES = 64 * 1024 * 1024     # 단일 파트 64MB
_MAX_XLSX_TOTAL_BYTES = 256 * 1024 * 1024   # 모든 파트 합 256MB

# OOXML 정상 xlsx 는 DOCTYPE / 외부 엔티티를 쓰지 않음.
# entity expansion (billion-laughs) DoS 차단을 위해 사전 거부.
_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE = re.compile(rb"<!ENTITY", re.IGNORECASE)


def _sanitize_xml_text(s):
    """XML 1.0 invalid control char 제거. None 은 빈 문자열로."""
    if s is None:
        return ""
    return _XML_INVALID_RE.sub("", str(s))


def _safe_parse_xlsx_part(data):
    """xlsx 내부 XML 파트를 안전하게 파싱.

    DOCTYPE/ENTITY 선언이 들어 있으면 거부 (정상 OOXML 에는 존재하지 않음).
    이를 통해 entity expansion 류 DoS 를 사전 차단.
    """
    if _DOCTYPE_RE.search(data) or _ENTITY_RE.search(data):
        raise ValueError("xlsx 파일이 DOCTYPE/ENTITY 선언을 포함하고 있어 거부했습니다.")
    return ET.fromstring(data)


# ---------------------------------------------------------------- helpers

def col_letter(idx):
    """0-based 컬럼 인덱스 -> 'A', 'B', ..., 'Z', 'AA', ..."""
    s = ""
    n = idx
    while True:
        s = chr(ord('A') + n % 26) + s
        n = n // 26 - 1
        if n < 0:
            break
    return s


def _ref_to_col_idx(ref):
    """'A1' -> 0, 'B1' -> 1, 'AA1' -> 26"""
    m = re.match(r"^([A-Z]+)\d+$", ref or "")
    if not m:
        return 0
    letters = m.group(1)
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - ord("A") + 1)
    return n - 1


# ---------------------------------------------------------------- 정적 part 들

CONTENT_TYPES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml"'
    ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    '<Override PartName="/xl/worksheets/sheet1.xml"'
    ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    '<Override PartName="/xl/styles.xml"'
    ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    '<Override PartName="/xl/sharedStrings.xml"'
    ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
    '<Override PartName="/docProps/core.xml"'
    ' ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    '<Override PartName="/docProps/app.xml"'
    ' ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    '</Types>'
)

ROOT_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1"'
    ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
    ' Target="xl/workbook.xml"/>'
    '<Relationship Id="rId2"'
    ' Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"'
    ' Target="docProps/core.xml"/>'
    '<Relationship Id="rId3"'
    ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"'
    ' Target="docProps/app.xml"/>'
    '</Relationships>'
)

WORKBOOK_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    '<fileVersion appName="nmapParser"/>'
    '<workbookPr/>'
    '<bookViews><workbookView xWindow="0" yWindow="0" windowWidth="20000" windowHeight="12000"/></bookViews>'
    '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
    '</workbook>'
)

DOCPROPS_CORE_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<cp:coreProperties'
    ' xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
    ' xmlns:dc="http://purl.org/dc/elements/1.1/"'
    ' xmlns:dcterms="http://purl.org/dc/terms/"'
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    '<dc:creator>nmapParser</dc:creator>'
    '<cp:lastModifiedBy>nmapParser</cp:lastModifiedBy>'
    '</cp:coreProperties>'
)

DOCPROPS_APP_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Properties'
    ' xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"'
    ' xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    '<Application>nmapParser</Application>'
    '<DocSecurity>0</DocSecurity>'
    '<ScaleCrop>false</ScaleCrop>'
    '<LinksUpToDate>false</LinksUpToDate>'
    '<SharedDoc>false</SharedDoc>'
    '<HyperlinksChanged>false</HyperlinksChanged>'
    '</Properties>'
)

WORKBOOK_RELS_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1"'
    ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
    ' Target="worksheets/sheet1.xml"/>'
    '<Relationship Id="rId2"'
    ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"'
    ' Target="styles.xml"/>'
    '<Relationship Id="rId3"'
    ' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"'
    ' Target="sharedStrings.xml"/>'
    '</Relationships>'
)

# OOXML 스펙 준수 — openpyxl "no default style" 같은 경고도 안 뜸.
# style 0 = default, style 1 = bold (헤더용).
STYLES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<numFmts count="0"/>'
    '<fonts count="2">'
    '<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font>'
    '</fonts>'
    '<fills count="2">'
    '<fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill>'
    '</fills>'
    '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    '<cellXfs count="2">'
    '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
    '</cellXfs>'
    '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    '<dxfs count="0"/>'
    '<tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>'
    '</styleSheet>'
)


# ---------------------------------------------------------------- writer

def _build_sheet_xml(rows, shared_str_idx, col_widths=None):
    """
    rows = list[list[str]]; 첫 행은 굵게 처리.
    shared_str_idx = {string -> index} (call 자가 채움)
    OOXML element 순서: dimension -> sheetViews -> sheetFormatPr -> cols -> sheetData -> pageMargins.
    """
    n_rows = len(rows)
    n_cols = max((len(r) for r in rows), default=1)
    last_ref = col_letter(max(0, n_cols - 1)) + str(max(1, n_rows))
    dimension = "A1" if n_rows == 0 else f"A1:{last_ref}"

    parts = []
    parts.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n')
    parts.append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
                 ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">')
    parts.append(f'<dimension ref="{dimension}"/>')
    parts.append('<sheetViews><sheetView tabSelected="1" workbookViewId="0"/></sheetViews>')
    parts.append('<sheetFormatPr defaultRowHeight="15"/>')

    if col_widths:
        parts.append('<cols>')
        for i, w in enumerate(col_widths, start=1):
            parts.append(
                f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>'
            )
        parts.append('</cols>')

    parts.append('<sheetData>')
    for r_idx, row in enumerate(rows, start=1):
        style_attr = ' s="1"' if r_idx == 1 else ''
        spans = f' spans="1:{max(1, len(row))}"' if row else ''
        parts.append(f'<row r="{r_idx}"{spans}>')
        for c_idx, val in enumerate(row):
            if val is None:
                continue
            text = "" if val is None else str(val)
            # shared string 등록
            if text not in shared_str_idx:
                shared_str_idx[text] = len(shared_str_idx)
            sidx = shared_str_idx[text]
            ref = col_letter(c_idx) + str(r_idx)
            parts.append(
                f'<c r="{ref}" t="s"{style_attr}><v>{sidx}</v></c>'
            )
        parts.append('</row>')
    parts.append('</sheetData>')
    parts.append('<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>')
    parts.append('</worksheet>')
    return ''.join(parts)


def _build_shared_strings_xml(shared_str_idx):
    """shared_str_idx 가 채워진 후 SharedStrings.xml 생성."""
    # 인덱스 순서로 정렬
    items = sorted(shared_str_idx.items(), key=lambda kv: kv[1])
    count = len(items)
    parts = []
    parts.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n')
    parts.append(
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        f' count="{count}" uniqueCount="{count}">'
    )
    for text, _ in items:
        # XML invalid control char 제거 (NSE 출력 등 \x00, \x07 같은 것 방지)
        clean_text = _sanitize_xml_text(text)
        escaped = xml_escape(clean_text)
        preserve = ' xml:space="preserve"' if (clean_text and clean_text != clean_text.strip()) else ''
        parts.append(f'<si><t{preserve}>{escaped}</t></si>')
    parts.append('</sst>')
    return ''.join(parts)


def write_xlsx(path, rows, col_widths=None):
    """
    rows 를 xlsx 로 저장 (atomic — tempfile + os.replace).
    - 모든 셀이 shared string (t="s") → Excel 에서 '-Pn', '=foo', '@bar' 도 절대 수식 해석 안 됨.
    - 첫 행은 굵게.
    - col_widths 가 주어지면 그 너비 적용.
    - **atomic**: 같은 디렉토리에 임시 파일로 먼저 쓴 후 os.replace 로 한 번에 교체.
      쓰기 도중 UNC 끊김 / 디스크 가득참 / Excel 잠금 등에서 원본 손상 방지.
    """
    shared_str_idx = {}  # text -> index
    sheet_xml = _build_sheet_xml(rows, shared_str_idx, col_widths)
    shared_strings_xml = _build_shared_strings_xml(shared_str_idx)

    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    # 같은 디렉토리에 .tmp 임시 파일 (다른 디렉토리면 os.replace 가 cross-device 실패할 수 있음)
    base = os.path.basename(path)
    tmp_path = os.path.join(parent or ".", f".{base}.tmp.{os.getpid()}")

    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
            z.writestr("_rels/.rels", ROOT_RELS_XML)
            z.writestr("docProps/core.xml", DOCPROPS_CORE_XML)
            z.writestr("docProps/app.xml", DOCPROPS_APP_XML)
            z.writestr("xl/workbook.xml", WORKBOOK_XML)
            z.writestr("xl/_rels/workbook.xml.rels", WORKBOOK_RELS_XML)
            z.writestr("xl/styles.xml", STYLES_XML)
            z.writestr("xl/sharedStrings.xml", shared_strings_xml)
            z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
        # atomic replace
        os.replace(tmp_path, path)
    except Exception:
        # 임시 파일 정리
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- reader

NS_MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


def read_xlsx(path):
    """
    xlsx 를 읽어 rows = list[list[str]] 로 반환.
    inline string / shared string / 일반 값 셀 모두 지원.
    """
    rows = []
    with zipfile.ZipFile(path, "r") as z:
        # zip-bomb / 비정상 파일 거부 — 압축 해제 크기 합산 검사.
        total = 0
        for info in z.infolist():
            if info.file_size > _MAX_XLSX_PART_BYTES:
                raise ValueError(
                    f"xlsx 내부 파트 크기 초과: {info.filename} ({info.file_size} bytes)"
                )
            total += info.file_size
            if total > _MAX_XLSX_TOTAL_BYTES:
                raise ValueError(f"xlsx 전체 압축 해제 크기 초과: {total} bytes")

        names = set(z.namelist())

        # shared strings 표 (사용자가 Excel 로 편집 후 저장하면 등장)
        shared = []
        if "xl/sharedStrings.xml" in names:
            ss_root = _safe_parse_xlsx_part(z.read("xl/sharedStrings.xml"))
            for si in ss_root.findall(NS_MAIN + "si"):
                # rich text 도 합쳐서 하나의 문자열로
                texts = []
                for t in si.iter(NS_MAIN + "t"):
                    if t.text:
                        texts.append(t.text)
                shared.append("".join(texts))

        # 첫 시트 찾기
        sheet_paths = [
            n for n in names
            if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
        ]
        if not sheet_paths:
            return []
        sheet_path = sorted(sheet_paths)[0]
        sheet_root = _safe_parse_xlsx_part(z.read(sheet_path))

        sheet_data = sheet_root.find(NS_MAIN + "sheetData")
        if sheet_data is None:
            return []

        for row_el in sheet_data.findall(NS_MAIN + "row"):
            cells = {}
            max_c = -1
            for cell in row_el.findall(NS_MAIN + "c"):
                ref = cell.get("r", "")
                col_idx = _ref_to_col_idx(ref)
                t = cell.get("t", "")
                value = ""
                if t == "inlineStr":
                    is_el = cell.find(NS_MAIN + "is")
                    if is_el is not None:
                        texts = [te.text or "" for te in is_el.iter(NS_MAIN + "t")]
                        value = "".join(texts)
                elif t == "s":
                    v_el = cell.find(NS_MAIN + "v")
                    if v_el is not None and v_el.text is not None:
                        try:
                            idx = int(v_el.text)
                            if 0 <= idx < len(shared):
                                value = shared[idx]
                        except ValueError:
                            pass
                elif t == "str":
                    # <c t="str"><v>text</v></c>
                    v_el = cell.find(NS_MAIN + "v")
                    if v_el is not None and v_el.text is not None:
                        value = v_el.text
                else:
                    # 숫자/기본 — <v> 의 raw text
                    v_el = cell.find(NS_MAIN + "v")
                    if v_el is not None and v_el.text is not None:
                        value = v_el.text
                cells[col_idx] = value
                if col_idx > max_c:
                    max_c = col_idx
            if max_c < 0:
                rows.append([])
            else:
                rows.append([cells.get(i, "") for i in range(max_c + 1)])
    return rows


# =========================================================================== multi-sheet writer
# 시간축 보고서 (현황/히트맵/변경이력/위험도추이/메타/NSE상세) 와 diff 색칠을 위해 사용.
# 단일시트 write_xlsx 와 별개의 styles.xml 을 사용해 색상 fill 9개 + 추가 cellXfs.

# 색상 fill 인덱스 (사용자 코드에서 row_fills 또는 cell_fills 로 지정):
#   FILL_NONE          = 0  # 기본 (무색)
#   FILL_NEW_OPEN      = 1  # 빨강  — 새 열린 포트 / NEW_OPEN
#   FILL_KEEP          = 2  # 하늘  — 유지된 열린 포트
#   FILL_CLOSED        = 3  # 자주  — 닫힘 / CLOSED
#   FILL_UNOBSERVED    = 4  # 회색  — 미관측 (해당 시점에 스캔 결과 없음)
#   FILL_CHANGED       = 5  # 노랑  — service/version 변경 / CHANGED
#   FILL_UNCHANGED     = 6  # 흰색  — UNCHANGED (FILL_NONE 과 동일하지만 명시)
#   FILL_HEADER        = 7  # 옅은 회색 — 헤더 시각 강조
#   FILL_RISK_HIGH     = 8  # 진한 빨강 — 위험도 상

FILL_NONE = 0
FILL_NEW_OPEN = 1
FILL_KEEP = 2
FILL_CLOSED = 3
FILL_UNOBSERVED = 4
FILL_CHANGED = 5
FILL_UNCHANGED = 6
FILL_HEADER = 7
FILL_RISK_HIGH = 8

# (R,G,B) hex (앞에 FF 붙여 ARGB).
_FILL_RGB = {
    FILL_NEW_OPEN:    "FFCDD2",  # 연한 빨강
    FILL_KEEP:        "BBDEFB",  # 연한 하늘
    FILL_CLOSED:      "E1BEE7",  # 연한 자주
    FILL_UNOBSERVED:  "EEEEEE",  # 회색
    FILL_CHANGED:     "FFF59D",  # 연한 노랑
    FILL_UNCHANGED:   "FFFFFF",  # 흰색 (시각 동등)
    FILL_HEADER:      "F5F5F5",  # 헤더 옅은 회색
    FILL_RISK_HIGH:   "EF9A9A",  # 진한 빨강
}


def _styles_xml_multi():
    """multi-sheet 용 styles.xml — 9개 fill + 매칭 cellXfs.
    cellXfs index = FILL_* 와 그대로 일치하지만 헤더용 (bold) 은 별도 인덱스 부여."""
    fills_xml = [
        '<fill><patternFill patternType="none"/></fill>',
        '<fill><patternFill patternType="gray125"/></fill>',
    ]
    # FILL_NEW_OPEN(1) ~ FILL_RISK_HIGH(8) 를 fills count 인덱스 2~9 에 매핑.
    for i in (FILL_NEW_OPEN, FILL_KEEP, FILL_CLOSED, FILL_UNOBSERVED,
              FILL_CHANGED, FILL_UNCHANGED, FILL_HEADER, FILL_RISK_HIGH):
        rgb = _FILL_RGB[i]
        fills_xml.append(
            f'<fill><patternFill patternType="solid">'
            f'<fgColor rgb="FF{rgb}"/><bgColor indexed="64"/>'
            f'</patternFill></fill>'
        )

    # cellXfs: index 0 default, 1 bold header (no fill), 2~9 = fill 매칭 (font0).
    # 헤더+필 = 10 (bold + FILL_HEADER), 11 (bold + FILL_RISK_HIGH).
    # _fill_xf_for_index() 는 fill 인덱스 → cellXfs 인덱스 매핑을 알고 있어야 함.
    cellxfs_parts = [
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>',                       # 0 default
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>',          # 1 bold header (no fill)
    ]
    # 인덱스 2~9 → fillId 2~9. font0.
    for fill_idx in range(2, 10):
        cellxfs_parts.append(
            f'<xf numFmtId="0" fontId="0" fillId="{fill_idx}" borderId="0"'
            f' xfId="0" applyFill="1"/>'
        )
    # 인덱스 10 = bold header + FILL_HEADER (fillId 8). 11 = bold header + FILL_RISK_HIGH (fillId 9).
    cellxfs_parts.append(
        f'<xf numFmtId="0" fontId="1" fillId="8" borderId="0" xfId="0"'
        f' applyFont="1" applyFill="1"/>'                                                        # 10 bold + header bg
    )
    cellxfs_parts.append(
        f'<xf numFmtId="0" fontId="1" fillId="9" borderId="0" xfId="0"'
        f' applyFont="1" applyFill="1"/>'                                                        # 11 bold + risk high
    )

    cellxfs_count = len(cellxfs_parts)
    fills_count = len(fills_xml)

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<numFmts count="0"/>'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/><family val="2"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font>'
        '</fonts>'
        f'<fills count="{fills_count}">' + ''.join(fills_xml) + '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        f'<cellXfs count="{cellxfs_count}">' + ''.join(cellxfs_parts) + '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '<dxfs count="0"/>'
        '<tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>'
        '</styleSheet>'
    )


def _fill_to_xf(fill_idx, *, header=False):
    """FILL_* 인덱스 → cellXfs 인덱스 변환.
    header=True 면 굵은 헤더 위에 배경색을 입힘 (FILL_HEADER → 10, FILL_RISK_HIGH → 11)."""
    if header:
        if fill_idx == FILL_HEADER:
            return 10
        if fill_idx == FILL_RISK_HIGH:
            return 11
        return 1  # bold default
    if not fill_idx:
        return 0
    if 1 <= fill_idx <= 8:
        # cellXfs index 2..9 매핑
        return fill_idx + 1
    return 0


def _build_multi_sheet_xml(sheet, shared_str_idx):
    """단일 시트 XML 생성 (multi-sheet writer 용).
    sheet = {"name", "headers", "rows", "row_fills"?, "cell_fills"?, "col_widths"?, "header_fill"?}
      - row_fills: list[int|None], 데이터 행마다 fill 인덱스. 행 전체에 적용.
      - cell_fills: list[list[int|None]], 셀 단위 fill (row_fills 와 동시 사용 시 cell 우선).
      - header_fill: int — 헤더 행 fill (FILL_HEADER 권장).
    """
    headers = sheet.get("headers") or []
    body_rows = sheet.get("rows") or []
    row_fills = sheet.get("row_fills") or [None] * len(body_rows)
    cell_fills = sheet.get("cell_fills") or [[] for _ in body_rows]
    header_fill = sheet.get("header_fill", FILL_NONE)
    col_widths = sheet.get("col_widths")

    all_rows = [headers] + list(body_rows)
    n_rows = len(all_rows)
    n_cols = max((len(r) for r in all_rows), default=1)
    last_ref = col_letter(max(0, n_cols - 1)) + str(max(1, n_rows))
    dimension = "A1" if n_rows == 0 else f"A1:{last_ref}"

    parts = []
    parts.append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n')
    parts.append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
                 ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">')
    parts.append(f'<dimension ref="{dimension}"/>')
    parts.append('<sheetViews><sheetView workbookViewId="0"/></sheetViews>')
    parts.append('<sheetFormatPr defaultRowHeight="15"/>')

    if col_widths:
        parts.append('<cols>')
        for i, w in enumerate(col_widths, start=1):
            parts.append(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>')
        parts.append('</cols>')

    parts.append('<sheetData>')
    for r_idx, row in enumerate(all_rows, start=1):
        is_header = (r_idx == 1)
        if is_header:
            row_xf = _fill_to_xf(header_fill, header=True)
        else:
            row_xf = _fill_to_xf(row_fills[r_idx - 2] if r_idx - 2 < len(row_fills) else None)

        spans = f' spans="1:{max(1, len(row))}"' if row else ''
        parts.append(f'<row r="{r_idx}"{spans}>')
        for c_idx, val in enumerate(row):
            if val is None:
                continue
            text = "" if val is None else str(val)
            if text not in shared_str_idx:
                shared_str_idx[text] = len(shared_str_idx)
            sidx = shared_str_idx[text]
            ref = col_letter(c_idx) + str(r_idx)

            # cell-level fill 우선
            cell_xf = row_xf
            if not is_header and r_idx - 2 < len(cell_fills):
                row_cell_fills = cell_fills[r_idx - 2]
                if c_idx < len(row_cell_fills) and row_cell_fills[c_idx]:
                    cell_xf = _fill_to_xf(row_cell_fills[c_idx])

            style_attr = f' s="{cell_xf}"' if cell_xf else ''
            parts.append(f'<c r="{ref}" t="s"{style_attr}><v>{sidx}</v></c>')
        parts.append('</row>')
    parts.append('</sheetData>')
    parts.append('<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>')
    parts.append('</worksheet>')
    return ''.join(parts)


def _build_multi_workbook_xml(sheet_names):
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<fileVersion appName="nmapParser"/>'
        '<workbookPr/>'
        '<bookViews><workbookView xWindow="0" yWindow="0" windowWidth="20000" windowHeight="12000"/></bookViews>'
        '<sheets>'
    ]
    for i, name in enumerate(sheet_names, start=1):
        safe_name = xml_escape(_sanitize_xml_text(name))[:31] or f"Sheet{i}"
        parts.append(f'<sheet name="{safe_name}" sheetId="{i}" r:id="rId{i}"/>')
    parts.append('</sheets></workbook>')
    return ''.join(parts)


def _build_multi_workbook_rels(n_sheets):
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    ]
    for i in range(1, n_sheets + 1):
        parts.append(
            f'<Relationship Id="rId{i}"'
            f' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"'
            f' Target="worksheets/sheet{i}.xml"/>'
        )
    next_id = n_sheets + 1
    parts.append(
        f'<Relationship Id="rId{next_id}"'
        f' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"'
        f' Target="styles.xml"/>'
        f'<Relationship Id="rId{next_id + 1}"'
        f' Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings"'
        f' Target="sharedStrings.xml"/>'
        '</Relationships>'
    )
    return ''.join(parts)


def _build_multi_content_types(n_sheets):
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    ]
    for i in range(1, n_sheets + 1):
        parts.append(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml"'
            f' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    parts.append(
        '<Override PartName="/xl/styles.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/sharedStrings.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '<Override PartName="/docProps/core.xml"'
        ' ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml"'
        ' ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
        '</Types>'
    )
    return ''.join(parts)


def write_xlsx_multi(path, sheets, *, atomic=True):
    """multi-sheet xlsx 저장 (per-row / per-cell 색칠 지원).

    sheets: list[dict]
      필수: name(str), headers(list[str]), rows(list[list[str]])
      옵션:
        row_fills: list[int|None]   — 데이터 행마다 FILL_* 인덱스 (헤더 제외)
        cell_fills: list[list[int|None]] — 셀 단위 색 (row_fills 와 같이 쓰면 cell 우선)
        col_widths: list[float]
        header_fill: int            — 헤더 행 색 (default FILL_NONE)
    """
    if not sheets:
        raise ValueError("write_xlsx_multi: sheets 가 비어 있습니다.")

    shared_str_idx = {}
    sheet_xmls = []
    sheet_names = []
    for s in sheets:
        sheet_xmls.append(_build_multi_sheet_xml(s, shared_str_idx))
        sheet_names.append(s.get("name") or f"Sheet{len(sheet_names)+1}")
    shared_strings_xml = _build_shared_strings_xml(shared_str_idx)

    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)

    base = os.path.basename(path)
    tmp_path = os.path.join(parent or ".", f".{base}.tmp.{os.getpid()}") if atomic else path

    try:
        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", _build_multi_content_types(len(sheets)))
            z.writestr("_rels/.rels", ROOT_RELS_XML)
            z.writestr("docProps/core.xml", DOCPROPS_CORE_XML)
            z.writestr("docProps/app.xml", DOCPROPS_APP_XML)
            z.writestr("xl/workbook.xml", _build_multi_workbook_xml(sheet_names))
            z.writestr("xl/_rels/workbook.xml.rels", _build_multi_workbook_rels(len(sheets)))
            z.writestr("xl/styles.xml", _styles_xml_multi())
            z.writestr("xl/sharedStrings.xml", shared_strings_xml)
            for i, sx in enumerate(sheet_xmls, start=1):
                z.writestr(f"xl/worksheets/sheet{i}.xml", sx)
        if atomic and tmp_path != path:
            os.replace(tmp_path, path)
    except Exception:
        if atomic and tmp_path != path:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
        raise
