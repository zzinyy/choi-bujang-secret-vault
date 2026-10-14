# 12단계 증거와 출처

제공 엔진: **ALEPH SDP 엔진**.
학생 작성: `src/decider.mjs` 판정기, `src/detect.mjs` 탐지 규칙, 접속 앱, 자료실, 작전실 및 HTTP 자기 점검.

`npm run decider:test`와 `npm run detect:test`는 가상 요청/사건 시험이다.
`propose_revocation`은 회수 제안이며 실제 회수 완료가 아니다.
작전실의 판정·탐지·회수·복구는 운영 기록에 연결되지 않아 미실행으로 표시한다.

## 실제 HTTP 자기 점검

`node scripts/operations-probe.mjs`는 설정의 실제 배포 주소에 무인증 GET 두 개를 보낸다.
작전실에서 기기 승인 후 “무인증 HTTP 자기 점검 실행”을 누르면 현재 배포 주소에 같은 요청을 보낸다.
정상 결과: 정적 자료의 빈 notes 배열, API의 401/403.
노출 결과: 정적 자료에 notes가 하나 이상 있음. API 200은 무인증 거부를 증명하지 않는다.
비 JSON·전송 오류·500 등은 방어 성공으로 처리하지 않는다.
브라우저 요청은 credentials: omit이며 로그인 토큰과 기기 서명을 보내지 않는다.

보고서는 실행 시작/종료 시각, 실제 HTTP 상태, 응답 헤더의 요청 식별자와 그 출처만 보존한다.
`x-vercel-id`는 Vercel 요청 식별자이며 심판 또는 ALEPH SDP 엔진 requestId가 아니다.
식별자가 제공되지 않으면 null로 남긴다. 메모 본문과 토큰은 기록하지 않는다.

## 공식 심판 실행과 제출

`scripts/bundle.mjs`는 attackAttempts에 attackId·expected·observed 세 필드만 허용한다.
현재 저장소와 참조 대화에는 공식 41종 목록과 해당 attackId 요청을 심판 실행 기록에 연결하는 계약이 없다.
따라서 step 12의 두 제출 항목은 observed: not_run이다.
학생 직접 HTTP 요청을 심판의 실행으로 가장하거나 요청 ID를 생성해 채우지 않는다.
41종의 실행 수는 확인 불가이며, 미제공 공격 이름이나 39개 결과를 만들지 않는다.

공식 「막혔을 때 넣을 프롬프트」와 기록 API 계약을 확인한 뒤,
그 계약에 따라 동일 제출본에 무인증 및 타인 메모 시험을 실행하고 가린 서버 기록과 대조해야 한다.
그 전에는 S12_SCREEN_MISMATCH 해결·41종 방어·12단계 통과를 주장하지 않는다.
미커밋 변경이 있으면 bundle 보호 장치를 그대로 유지한다.

## 남은 원격 검증

정상 사용자 두 계정의 로그인·기기 승인·타인 메모 격리,
미등록/회수 기기 재접속, 복구 전후 소유권·서명·감사 기록,
실제 복구 결과는 원격에서 확인해야 한다.
복구/회수 시험용 계정과 가상 자료만 사용하며 운영 자료는 시험에 쓰지 않는다.

2026-10-14 원격 메타데이터 조회: stage10_note_backups, stage10_policy_audit,
stage11_devices 테이블 존재와 RLS 활성화를 확인했다. notes도 RLS 활성화이며
소유자 조건 SELECT/INSERT/UPDATE/DELETE 정책이 있다.
네 테이블에 anon/authenticated 직접 권한은 조회되지 않았다.
stage10_restore_note_atomic은 SECURITY DEFINER이며 postgres/service_role만 실행 권한이 있다.
이 조회에서는 메모·계정·기기 행을 읽거나 변경하지 않았다.
