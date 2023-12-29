from datetime import timezone

from django.http import JsonResponse
from django.shortcuts import render, redirect
from .models import *
from django.core.paginator import Paginator
from django.core.files.storage import  FileSystemStorage
from datetime import timezone

from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from .models import *
from django.core.paginator import Paginator
from django.core.files.storage import  FileSystemStorage

import json
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Embedding, GlobalAveragePooling1D
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.preprocessing import image
from PIL import Image

import os
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.utils import timezone
from .utils import get_tokens_for_user
import requests
import uuid

import string
import secrets
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password

load_dotenv()
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

# Create your views here.

def index(request) :
    print('debug >>> mainApp /index')
    return render(request, 'mainpage/index.html')


def scalp(request) :
    print('debug >>> mainApp /scalp')
    return render(request, 'mainpage/scalp.html')


def shampoo(request) :
    print('debug >>> mainApp /shampoo')
    return render(request, 'mainpage/shampoo.html')


def my(request) :
    print('debug >>> mainApp /my')
    return render(request, 'mainpage/my.html')


def login(request) :
    print('debug >>> mainApp /login')
    print('debug >>> request method ', request.method)
    try:
        if request.method == "POST":
            username = request.POST.get("id")
            password = request.POST.get("pwd")
            print("debug params >>> ", username, password)

            # 로그인 실패 기록 확인
            fail_count_key = f"login_fail_{username}"
            fail_count = cache.get(fail_count_key, 0)

            # 임계값 초과 시
            if fail_count >= 11:
                last_attempt_time = cache.get(f"{fail_count_key}_time")
                if last_attempt_time and timezone.now() < last_attempt_time + timezone.timedelta(minutes=5):
                    return HttpResponse("로그인이 일시적으로 차단되었습니다. 5분 후에 다시 시도해주세요.")

            try:
                user = User_tbl.objects.get(user_id=username, user_pwd=password)
                print('debug >>> user ', user)
                if user is not None: # 로그인 성공
                    # 실패 카운트 초기화
                    cache.delete(fail_count_key)
                    cache.delete(f"{fail_count_key}_time")
                    # 로그인 처리
                    request.session['user_id'] = user.user_id
                    print('debug >>> 로그인 성공!')
                    context = {'message': '로그인 성공!'}
                    return render(request, 'mainpage/index.html', context=context)
            except User_tbl.DoesNotExist:
                print('debug >>> 로그인 실패 1: ', request)
                cache.set(fail_count_key, fail_count + 1, timeout=300)  # 실패 카운트 증가
                print('fail_count: ', fail_count)
                if fail_count == 0:
                    cache.set(f"{fail_count_key}_time", timezone.now(), timeout=300)
                return render(request, 'mainpage/login.html', {'message': '아이디와 비밀번호를 다시 확인해주세요'})
        else:
            print('debug >>> 로그인 실패 2')
            return render(request, 'mainpage/login.html')
    except Exception as e:
        print('debug >>> 예외 발생 2: ', e)
        return render(request, 'mainpage/login.html')


def join(request) :
    print('debug >>> mainApp /join')
    return redirect('register')


# media 폴더에 사진 업로드
def upload(request) :
    print('debug >>>> upload ')
    file = request.FILES['image']
    print('debug >>>> img ' , file , file.name)
    fs = FileSystemStorage()
    fileName = fs.save(file ,file)
    print('debug >>>> filename ', fileName)
    img_file = Image.open(file)
    img_file = img_file.resize((60, 80))
    img = image.img_to_array(img_file)
    img = img.reshape(1, img.shape[0], img.shape[1], img.shape[2])
    # 모델 위치는 본인 컴퓨터 환경에 맞춰서 재설정 부탁드립니다 !
    pre_train_model = keras.models.load_model('C:/Users/user/PycharmProjects/Team2PJT/rootWEB/mainApp/static/hair_predict_model2')
    guess = pre_train_model.predict(img)
    labels = ['양호', '경증 비듬', '중등도 비듬', '중증 비듬', '경증 탈모', '중등도 탈모', '중증 탈모']
    links  = ['/shampoo', '/dandruff', '/dandruff', '/dandruff', '/loss', '/loss', '/loss']
    predicted_label = labels[np.argmax(guess)]
    links_label     = links[np.argmax(guess)]
    return render(request, 'mainpage/scalp_result.html', {'predicted_label': predicted_label, 'fileName' : fileName, 'links_label' : links_label})


def shampooButton(request):
    return render(request, 'mainpage/loss.html')

def loss(request) :
    print('debug >>> mainApp /loss')
    return render(request, 'mainpage/loss.html')

def dandruff(request) :
    print('debug >>> mainApp /dandruff')
    return render(request, 'mainpage/dandruff.html')


def logout_view(request):
    if 'user_id' in request.session:
        del request.session['user_id']
        print('debug >>> user deleted')
    return redirect('index')


def register(request):
    try:
        if request.method == 'POST':
            id = request.POST['id']
            pwd = request.POST['pwd']
            email = request.POST['email']
            User_tbl.objects.create(user_id=id, user_pwd=pwd, user_email=email)
            return redirect('login')
        return render(request, 'mainpage/register.html')
    except Exception as e:
        print('debug >>> Exception: ', e)
        return render(request, 'mainpage/register.html')


def find_my_account(request) :
    print('debug >> mainApp /find_pwd')
    return render(request, 'mainpage/find_my_account.html')


def google_auth(request):
    # Google OAuth 설정
    flow = Flow.from_client_secrets_file(
        'client_secrets.json',
        scopes=['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email'],
        redirect_uri='http://127.0.0.1:8000/auth/google/callback'
    )

def check_user_id(request):
    user_id = request.GET.get('id', None)
    is_taken = User_tbl.objects.filter(user_id=user_id).exists()
    return JsonResponse({'is_taken': is_taken})

def check(request) :
    print('debug >> mainApp /find_pwd')
    return render(request, 'mainpage/check.html')


from django.views import View
class KakaoSignInCallBackView(View):
    def get(self, request):
        auth_code = request.GET.get('code')
        kakao_token_api = "https://kauth.kakao.com/oauth/token"
        data = {
            'grant_type'      : 'authorization_code',
            'client_id'       : os.getenv('REST_API_KEY'),
            'redirection_uri' : "http://127.0.0.1:8000/oauth/kakao/callback",
            'code'            : auth_code,
        }
        token_response   = requests.post(kakao_token_api, data=data)
        access_token     = token_response.json().get('access_token')
        kakao_user_api   = "https://kapi.kakao.com/v2/user/me"
        header           = {"Authorization": f"Bearer ${access_token}"}
        user_information = requests.get(kakao_user_api, headers=header).json()
        kakao_id         = user_information["id"]
        request.session['user_id'] = kakao_id
        return redirect('/scalp/')


def show_id(request):
    print('debug >> mainApp /show_id')
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = User_tbl.objects.get(user_email=email)
            print('debug >>>>> user: ', user)
            return JsonResponse({'user_id': user.user_id})
        except User_tbl.DoesNotExist:
            return JsonResponse({'error': '사용자를 찾을 수 없습니다.'}, status=404)
    return JsonResponse({'error': 'Invalid request'}, status=400)


def reset_password(request):
    print('debug >> mainApp /find_pwd')
    if request.method == 'POST':
        username = request.POST.get('id')
        email = request.POST.get('email')

        # 사용자 검증 및 임시 비밀번호 생성 및 이메일 전송 로직 구현.
        try:
            user = User_tbl.objects.get(user_id=username, user_email=email)
            # print('debug >>>>> ' , user)
        except User_tbl.DoesNotExist:
            return JsonResponse({'error': '사용자를 찾을 수 없습니다.'}, status=404)

        # 임시 비밀번호 생성
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for i in range(8))
        # 생성된 비밀번호 저장 - 방법 1
        # hashed_password = make_password(new_password)
        # user.user_pw = hashed_password
        # 생성된 비밀번호 저장 - 방법 2
        user.user_pwd = new_password
        # print('debug >>>>> change pwd ' , user.user_pwd)
        user.save()

        # 이메일 전송
        send_mail(
            'Your New Password',
            f'Your new password is: {new_password}',
            "jhasadf@gmail.com",# 발신자 이메일 주소
            [user.user_email],  # 수신자 이메일 주소
            fail_silently=False,
        )
        return JsonResponse({'message': '임시 비밀번호가 이메일로 발송되었습니다.'})

    return JsonResponse({'error': 'Invalid request'}, status=400)
