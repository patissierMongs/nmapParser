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
