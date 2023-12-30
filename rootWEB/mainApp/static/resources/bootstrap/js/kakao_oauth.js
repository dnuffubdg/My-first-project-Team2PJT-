Kakao.init('d8fa61f9205974a778331d9f768fec30');

function kakaoRegister() {
  Kakao.Auth.authorize({
    redirectUri: 'http://127.0.0.1:8000/oauth/kakao/callback',
  });
}

function displayToken() {
  var token = getCookie('authorize-access-token');
  if (token) {
    Kakao.Auth.setAccessToken(token);
    Kakao.Auth.getStatusInfo().then(function(res) {
      if (res.status === 'connected') {
        document.getElementById('token-result').innerText = 'login success, token: ' + Kakao.Auth.getAccessToken();
      }
    }).catch(function(err) {
      Kakao.Auth.setAccessToken(null);
    });
  }
}

function getCookie(name) {
  var parts = document.cookie.split(name + '=');
  if (parts.length === 2) {
    return parts[1].split(';')[0];
  }
}

displayToken(); // 함수 호출 위치 변경