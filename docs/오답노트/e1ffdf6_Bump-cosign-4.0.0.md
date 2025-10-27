\# Bandit 커밋 분석 - e1ffdf6



\## 개요

\- 변경: sigstore/cosign-installer 3.10.0 → 4.0.0

\- 영향 파일: .github/workflows/release.yml

\- 관련 PR: #1317



\## 배경

\- cosign-installer는 GitHub Actions에서 릴리즈 서명 자동화를 담당.

\- 구버전(3.10.0)에서 의존 모듈 업데이트와 서명 검증 로직 관련 취약점(CVE-2024-44255 등)이 보고됨.



\## 분석

```diff

\- uses: sigstore/cosign-installer@v3.10.0

\+ uses: sigstore/cosign-installer@v4.0.0

```



\## 변경 요약

\- cosign-installer는 GitHub Actions 환경에서 Cosign(서명 및 검증 도구) 을 설치하는 액션

\- v4.0.0에서는 Cosign v3 릴리스 지원이 추가되었으며, --bundle 플래그를 사용해야 하는 새로운 서명 명령 형식을 지원

\- 여전히 Cosign v2.x 버전도 설치 가능 => 하위 호환성 유지

결론 : Bandit의 릴리즈 파이프라인에서 사용하는 서명 도구의 버전 업그레이드를 반영한 것



| 구분           | v3.10.0                | v4.0.0                 | 보안적 의미                       |

| ------------ | ---------------------- | ---------------------- | ---------------------------- |

| 지원 Cosign 버전 | v2.6.0                 | v2.x + v3.x            | 최신 서명 체계 호환                  |

| 서명 명령 형식     | legacy (`cosign sign`) | `cosign sign --bundle` | \*\*메타데이터 포함된 서명 구조 (무결성 강화)\*\* |

| 검증 로직        | 단순 서명 검증               | 번들 기반 서명 검증            | \*\*검증 강도 상승\*\*                 |

| 공급망 신뢰성      | 구버전 릴리즈 체인             | 최신 sigstore 정책 적용      | \*\*서명 신뢰도 향상\*\*                |



&nbsp; 

\## 추가 검증 포인트

\- PR #1317 본문 및 리뷰를 통해 변경 이유 확인.

&nbsp; - 자동 bump인지 / 보안 대응인지 명시 여부 확인.

\- cosign-installer v4.0.0 릴리즈 노트

&nbsp; - Cosign v3 지원 및 플래그 변경(--bundle) 추가 내용 확인.

&nbsp; - CVE 관련 내용은 현재 없음.

\- Bandit CI 빌드 로그 확인

&nbsp; - cosign version이 v3 이상으로 정상 출력되는지, 릴리즈 시 서명/검증 절차가 정상 동작하는지 확인.

\- 로컬 재현 실험

&nbsp; - 동일 GitHub Actions 환경에서 cosign v3 설치 및 서명 명령(cosign sign --bundle) 수행 후 검증 테스트.



\## 결론 및 시사점

\- 보안적 의미:

&nbsp; - 최신 Cosign(v3) 체계로 전환하면서 릴리즈 서명 신뢰성이 강화됨.

&nbsp; - 향후 공급망 공격(예: 릴리즈 변조, 무서명 바이너리 배포)에 대한 방어력 향상.

\- 리스크:

&nbsp; - 일부 자동화 스크립트나 CI 설정에서 cosign sign 명령 플래그가 맞지 않으면 빌드 실패 가능 → 설정 점검 필요.

\- 평가:

&nbsp; - 보안성 향상 업데이트 (권장).

&nbsp; - CI 환경 호환성 검토 필요.



\## 참고 자료

\- PR: PyCQA/bandit#1317

\- cosign-installer 릴리즈 페이지: v4.0.0

\- CI 워크플로우 파일: .github/workflows/release.yml

\- 관련 개념: Sigstore 공식 문서 / Software Supply Chain Security 가이드

