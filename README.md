닷넷 코어 6.0 API JWT 토큰/Refresh 토큰 샘플 (2Factor 인증 처리 포함)



DATABASE
```
[EF Core(패키지 관리자 콘솔)]
Add-Migration InitialCreate
Update-Database
```

API
```
1. 등록 (이메일 발송)
2. 등록 확인(발송된 이메일에 포함된 토큰으로 등록완료)

3. 로그인 (인증 번호 이메일에 발송)
4. 로그인 인증 번호 입력을 통해 로그인 완료

5. 비밀번호 초기화 요청(비번 초기화 토큰 이메일 발송)
6. 초기화 토큰을 통한 비밀번호 변경 

7. 리프레시 토큰

8. 토큰 만료 테스트를 위한 테스트 API

```

#2022-10-14

추가사항
```
1. 구글 OTP 인증 기능 추가
```
