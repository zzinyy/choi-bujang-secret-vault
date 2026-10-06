# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 2단계 · 자료를 코드 밖으로 옮깁니다

- 공개 정적 `data.json`에서는 가상 메모 본문을 제거했습니다.
- 학습용 Supabase `notes` 테이블에 가상 메모 4건을 저장하며 `owner_id uuid` 칸을 두고 RLS를 활성화합니다.
- `anon`과 `authenticated`에는 테이블 직접 읽기 권한을 부여하지 않습니다.
- 화면은 정적 `/data.json` 대신 Vercel 서버 함수 `/api/notes`를 호출해 Supabase의 가상 메모를 읽습니다.
- `/api/notes`는 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 Vercel 환경변수에서 읽습니다.
- 서버 전용 키 값은 브라우저 파일, API 응답, 로그 또는 Git 저장소에 포함하지 않습니다.
- 이전 Git 커밋과 Vercel 배포 이력에 남아 있던 공개 가상 메모는 이 변경으로 삭제되지 않습니다.

### 현재 남아 있는 약점

2단계의 `/api/notes` 함수에는 아직 사용자 인증이 적용되지 않았습니다.

따라서 정적 `/data.json`에서는 메모가 제거되었지만 `/api/notes`는 아직 공개 주소입니다. 주소를 아는 사용자는 로그인 없이 직접 호출하여 가상 메모를 읽을 수 있습니다.

이 공개 API 접근 문제는 다음 인증 단계에서 보호해야 합니다.

### 로컬 빌드 확인

다음 명령으로 정적 빌드를 확인합니다.

`npm run build -- --local`

실제 Supabase 연결은 Vercel의 서버 환경변수 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 사용하며, 비밀값은 저장소에 기록하지 않습니다.

## 2단계 추가 확인 · 현재 파일과 과거 노출

### 현재 파일 확인 절차

현재 Vercel 배포의 `/data.json`을 직접 열어 정적 파일에 가상 메모가 남아 있는지 확인합니다.

`https://<현재-배포주소>/data.json`

정상적인 현재 배포에서는 `notes`가 다음과 같이 빈 배열이어야 합니다.

`"notes": []`

GitHub 최신 `main` 브랜치의 추적 파일에 가상 메모 문장이 남아 있는지는 다음 명령으로 확인합니다.

`git grep -n "실습용 가상"`

### 실제 확인 결과

현재 Vercel 배포의 `/data.json`에서는 가상 메모 본문이 제거되어 있으며 `notes`는 빈 배열입니다. 화면에 표시되는 가상 메모 네 건은 정적 `/data.json`이 아니라 Vercel 서버 함수 `/api/notes`를 통해 읽습니다.

GitHub 최신 파일에서 `git grep -n "실습용 가상"`을 실행한 결과, README의 검색 명령 예시와 `supabase/step2_notes.sql`의 초기 데이터 입력 구문에서 가상 메모 문장이 검색됩니다. 따라서 GitHub 최신 파일 전체에서 가상 메모 문장이 완전히 제거되었다고 기록하지 않습니다.

`supabase/step2_notes.sql`에 검색되는 가상 메모 문장은 Supabase 초기 데이터 입력 구문에 포함되어 있으며 현재 Vercel의 정적 `/data.json`에서 직접 제공되는 메모는 아닙니다.

### 남아 있는 공개 API 약점

`/api/notes`에는 아직 사용자 인증이 적용되지 않았습니다. 따라서 공개된 `/api/notes` 주소를 직접 요청하면 로그인하지 않은 사용자도 가상 메모를 읽을 수 있습니다. 정적 `/data.json`에서 메모를 제거한 것만으로 접근 통제가 완료된 것은 아닙니다.

또한 이전 Git 커밋과 이전 Vercel 배포에는 가상 메모가 공개되었던 이력이 남아 있습니다. 옛 공개 커밋과 옛 배포가 접근 가능한 동안에는 과거 노출이 해소되었다고 판단하거나 기록하지 않습니다.

## 2단계 저장점

현재 상태를 BYTE BACK 방어전 2단계 저장점으로 기록합니다.

## 3단계 · 진짜 로그인을 붙입니다

현재 상태를 BYTE BACK 방어전 3단계 저장점으로 기록합니다.

### 구현된 기능

- Supabase Auth의 이메일과 비밀번호 로그인을 사용합니다.
- 로그인 성공과 실패 결과를 화면에서 확인할 수 있습니다.
- 로그인한 사용자는 로그아웃할 수 있습니다.
- 브라우저는 Supabase에서 발급받은 access token을 Authorization Bearer 헤더로 자료 API에 전달합니다.
- 서버는 기존 `src/verify-login.mjs`를 사용하여 로그인 토큰을 검증합니다.
- 인증되지 않은 요청에는 메모 데이터를 반환하지 않습니다.
- 서버 전용 `SUPABASE_SECRET_KEY`의 실제 값은 브라우저 코드나 Git 저장소에 저장하지 않습니다.

### 메모 API

현재 허용된 자료 API 경로는 다음과 같습니다.

- `GET /api/notes`
- `POST /api/notes`
- `GET /api/notes/:id`
- `PUT /api/notes/:id`
- `DELETE /api/notes/:id`

`GET /api/notes`는 인증된 사용자의 `owner_id`와 일치하는 메모 목록을 반환합니다.

`POST /api/notes`는 브라우저가 보낸 사용자 ID나 역할을 신뢰하지 않고, 검증된 로그인 사용자의 ID를 `owner_id`로 저장합니다. 메모 ID는 UUID를 사용합니다.

단건 `GET`, `PUT`, `DELETE` 요청도 로그인이 필요합니다.

3단계에서는 단건 API에 메모 소유자 검사를 아직 적용하지 않습니다. 따라서 인증된 다른 사용자가 메모 ID를 알고 있는 경우 다른 사용자의 메모에 접근할 수 있는 상태이며, 이 부분은 다음 소유권 보호 단계에서 수정할 대상입니다.

### Supabase 자료 구조

`public.notes` 테이블의 메모 ID는 3단계에서 UUID로 전환했습니다.

기존 가상 메모는 유지하며 다음 필드를 사용합니다.

- `id`: UUID 메모 식별자
- `owner_id`: 메모를 생성한 인증 사용자 ID
- `title`: 메모 제목
- `content`: 메모 본문
- `created_at`: 생성 시각

RLS는 활성화되어 있으며 `anon`과 `authenticated` 역할에는 테이블 직접 접근 권한을 부여하지 않습니다. 자료 접근은 서버 API를 통해 수행합니다.

### 인증 공급자

`aleph.config.json`의 `identityProvider`에는 Supabase Auth의 공개 발급자 정보와 JWKS 주소, audience만 기록합니다.

비밀번호, access token, 서버 전용 키는 설정 파일에 기록하지 않습니다.

`judgeIssuer`는 과제에서 제공된 값을 그대로 유지합니다.

### 로컬 빌드 확인

다음 명령으로 공개 정적 파일 생성을 확인합니다.

`npm run build -- --local`

정상 실행 시 메모 원문을 포함하지 않는 `public/data.json`이 생성됩니다.

### 직접 확인할 동작

시크릿 창처럼 로그인 세션이 없는 상태에서는 메모 데이터에 접근할 수 없어야 합니다.

A 계정으로 로그인하면 A가 소유한 메모만 조회하고 추가, 수정, 삭제할 수 있어야 합니다.

B 계정으로 로그인하면 B가 소유한 메모만 표시되며 A가 소유한 메모는 목록에 표시되지 않아야 합니다.

B 계정으로 A 소유 메모의 ID를 직접 지정해 조회, 수정, 삭제를 시도하면 모두 거부되어야 합니다.

Supabase의 notes 테이블은 authenticated 역할에 SELECT, INSERT, UPDATE, DELETE 권한을 부여하되 RLS 정책을 통해 auth.uid()와 owner_id가 일치하는 행만 접근할 수 있도록 제한합니다.

### 4단계 저장점

4단계에서는 서버가 검증한 로그인 사용자 ID와 메모의 owner_id를 비교하여 다른 사용자의 메모에 접근할 수 없도록 수정했습니다.

메모 목록과 단건 조회, 추가, 수정, 삭제는 모두 로그인한 사용자의 소유권을 기준으로 처리하며 요청 URL이나 본문에서 전달되는 소유자 정보는 신뢰하지 않습니다.

로컬 빌드는 다음 명령으로 다시 확인할 수 있습니다.

`npm run build -- --local`

배포 후 `/aleph.json`의 step이 4인지 확인하고 A와 B 계정으로 각각 자신의 메모만 접근할 수 있는지 확인합니다.

### 현재 저장점 주의사항

과거 Git 커밋과 과거 Vercel 배포에 존재했던 공개 상태는 현재 파일을 수정하는 것만으로 삭제되지 않습니다.

현재 저장점에서는 정적 `/data.json`에 메모 원문을 넣지 않고 인증된 자료 요청은 서버 API를 통해 처리하며, API 소유권 검사와 Supabase RLS를 함께 적용합니다.

## 5단계 · 자료 요청을 서버 한곳으로 모읍니다

현재 상태를 BYTE BACK 방어전 5단계 저장점으로 기록합니다.

### 구현한 기능

- 브라우저의 메모 읽기, 추가, 수정, 삭제는 Vercel `/api/notes` 서버 함수를 통해 처리합니다.
- Supabase Auth 로그인 기능은 유지합니다.
- `public.notes` 테이블의 PUBLIC, anon, authenticated 직접 권한을 회수했습니다.
- 서버 함수의 로그인 검증과 `owner_id` 소유자 검사는 그대로 유지합니다.
- Supabase 원본 자료 API는 공개 키만으로 직접 조회할 수 없습니다.
- `aleph.config.json`의 `originalApiUrl`에는 쿼리 없는 Supabase notes 원본 API 경로를 기록합니다.

### 허용된 서버 API

- `GET /api/notes`
- `POST /api/notes`
- `GET /api/notes/:id`
- `PUT /api/notes/:id`
- `DELETE /api/notes/:id`

### 직접 확인한 동작

A 계정에서 메모 조회, 추가, 수정, 삭제가 서버 함수를 통해 정상 동작합니다.

B 계정에서는 B가 소유한 메모만 표시되고 A의 메모는 표시되지 않습니다.

로그아웃 상태에서는 메모 자료에 접근할 수 없습니다.

Supabase 원본 `notes` REST API를 공개 키만 사용해 직접 요청하면 `401 Unauthorized`와 `permission denied for table notes`가 반환됩니다.

`PUBLIC`, `anon`, `authenticated`의 `public.notes` 직접 테이블 권한을 확인한 결과 모두 회수된 상태입니다.

### 다시 실행하는 방법

로컬 공개 파일 빌드는 다음 명령으로 확인합니다.

`npm run build -- --local`

배포 후 `/aleph.json`에서 `step`이 5이고 `originalApiUrl`과 `allowedRoutes`가 올바르게 기록되어 있는지 확인합니다.

현재 메모 데이터 접근은 Vercel 서버 API로 모으고 Supabase 원본 테이블에 대한 브라우저 역할의 직접 접근은 허용하지 않습니다.