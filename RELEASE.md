# Release 가이드 (main + x86)

이 저장소는 `.github/workflows/build-windows-x86.yml`로 **Windows x86(32-bit)** 빌드를 지원합니다.

## 동작 방식
- `push tags: v*` -> x86 GUI onefile exe + x86 CLI onefile exe + x86 onedir zip 빌드 후 GitHub Release 자산 업로드
- `workflow_dispatch` -> 수동 빌드/아티팩트 업로드

## 릴리즈 전 로컬 점검

릴리즈 태그를 만들기 전에 최소 아래를 통과시킵니다.

```bash
python scripts/preflight_checks.py
python -m unittest discover -v
python nmapParser.py --check-config --options options.xlsx --categories categories.xlsx
```

확인 포인트:
- README/CLI 옵션 동기화 통과
- `py_compile` 통과
- 기본 `options.xlsx` / `categories.xlsx` 설정 검사 OK
- 전체 unittest 통과
- 가능하면 Windows Actions 아티팩트에서 `nmapParser.exe --check-config` 도 한 번 실행

## main 반영 후 x86 릴리즈 절차

1. 작업 브랜치 PR 머지 (target: `main`)
2. 로컬 최신화
   ```bash
   git checkout main
   git pull origin main
   ```
3. 릴리즈 태그 생성/푸시 (`v1.2.3` 형식)
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```
4. Actions `build-windows-x86` 실행 확인
5. GitHub Release에 아래 파일이 업로드됐는지 확인
   - `nmapParser.exe` (x86 GUI onefile)
   - `nmapParser-cli.exe` (x86 console onefile; `--check-config`/자동화용)
   - `nmapParser-x86.zip` (x86 onedir)

## 참고
- `main` push 자체는 기본적으로 **릴리즈 업로드를 트리거하지 않음**
- 릴리즈 자산 배포는 **태그 push**가 기준
