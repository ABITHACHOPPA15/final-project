# Create your views here.
from django.shortcuts import render, HttpResponse
from django.contrib import messages
from .forms import UserRegistrationForm
from .models import UserRegistrationModel, TokenCountModel, UserFilesModel
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from datetime import datetime, timedelta
from jose import JWTError, jwt
import numpy as np
import os

SECRET_KEY = "ce9941882f6e044f9809bcee90a2992b4d9d9c21235ab7c537ad56517050f26b"
ALGORITHM = "HS256"


def create_access_token(data: dict):
    to_encode = data.copy()
    # expire time of the token
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    # return the generated token
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HttpResponse(
            status_code=HttpResponse(status=204),
            detail="Could not validate credentials",
        )


# Create your views here.
def UserRegisterActions(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            print('Data is Valid')
            loginId = form.cleaned_data['loginid']
            TokenCountModel.objects.create(loginid=loginId, count=0)
            form.save()
            messages.success(request, 'You have been successfully registered')
            form = UserRegistrationForm()
            return render(request, 'UserRegistrations.html', {'form': form})
        else:
            messages.success(request, 'Email or Mobile Already Existed')
            print("Invalid form")
    else:
        form = UserRegistrationForm()
    return render(request, 'UserRegistrations.html', {'form': form})


def UserLoginCheck(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('pswd')
        print("Login ID = ", loginid, ' Password = ', pswd)
        try:
            check = UserRegistrationModel.objects.get(loginid=loginid, password=pswd)
            status = check.status
            print('Status is = ', status)
            if status == "activated":
                request.session['id'] = check.id
                request.session['loggeduser'] = check.name
                request.session['loginid'] = loginid
                request.session['email'] = check.email
                data = {'loginid': loginid}
                token_jwt = create_access_token(data)
                request.session['token'] = token_jwt
                print("User id At", check.id, status)
                return render(request, 'users/UserHomePage.html', {})
            else:
                messages.success(request, 'Your Account Not at activated')
                return render(request, 'UserLogin.html')
        except Exception as e:
            print('Exception is ', str(e))
            pass
        messages.success(request, 'Invalid Login id and password')
    return render(request, 'UserLogin.html', {})


def UserHome(request):
    return render(request, 'users/UserHomePage.html', {})


def DatasetView(request):
    return render(request, 'users/viewdataset.html', {})


def NISTTest(request):
    if request.method == 'POST':
        image_file = request.FILES['file']
        fs = FileSystemStorage(location="media/actual/")
        filename = fs.save(image_file.name, image_file)
        # detect_filename = fs.save(image_file.name, image_file)
        uploaded_file_url = "/actual/" + filename  # fs.url(filename)
        from .utility.nistiso_samples import star_process
        key, cipher = star_process(filename)
        loginid = request.session['loginid']
        email = request.session['email']
        # UserFilesModel.objects.all().delete()
        UserFilesModel.objects.create(username=loginid, email=email, filename=filename,
                                      enckey=key.decode(), file=uploaded_file_url)

        return render(request, "users/UploadForm.html", {'cipher': cipher})
    else:
        return render(request, "users/UploadForm.html", {})
    return HttpResponse('working')


def ViewFiles(request):
    loginid = request.session['loginid']
    data = UserFilesModel.objects.filter(username=loginid)
    response = HttpResponse('text/csv')
    return render(request, "users/viewUploadedFiles.html", {"data": data})


def download(request):
    fileis = request.GET.get('fileis')
    file_path = os.path.join(settings.MEDIA_ROOT, 'actual', fileis)
    print("Path of File is:", file_path)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/text")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response


def dataDecrypt(request):
    fid = request.GET.get('id')
    fileData = UserFilesModel.objects.get(id=fid)
    filename = fileData.filename
    encKey = fileData.enckey
    # encKey = bytes(encKey, 'utf-8')
    from .utility.decryptDatafiles import star_process
    decrypted = star_process(filename, encKey)
    file_path = os.path.join(settings.MEDIA_ROOT, 'decrypted', filename)
    with open(file_path, "w") as f:
        f.write(decrypted)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/text")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(file_path)
            return response


def reviewYourNIST(request):
    if request.method == 'POST':
        firstFile = request.FILES['file']
        fs1 = FileSystemStorage(location="media/review/")
        firstFile = fs1.save(firstFile.name, firstFile)
        secondFile = request.FILES['file1']
        fs2 = FileSystemStorage(location="media/review/")
        filename2 = fs2.save(secondFile.name, secondFile)
        # detect_filename = fs.save(image_file.name, image_file)

        from .utility.nistiso_review import star_process
        result = star_process(firstFile,filename2)

        return render(request, "users/ReviewForm.html", {"msg": result})
    else:
        return render(request, "users/ReviewForm.html", {})
    return HttpResponse('working')
