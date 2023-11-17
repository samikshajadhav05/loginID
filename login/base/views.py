from base64 import urlsafe_b64decode
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login,logout
from loginform import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from .tokens import generate_token
  
from django.core.mail import EmailMessage  
from django.contrib.auth import get_user_model
from django.http import HttpResponse

import loginform

def home(request):
    return render(request , "base/index.html")

def signup(request):
    
    if request.method == "POST":
    
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        password = request.POST.get('password')
        conform = request.POST.get('conform') 

        if User.objects.filter(username=username):
            messages.error(request, "User already exists\nPlease enter other username")
            return redirect('signup')

        if User.objects.filter(email=email):
            messages.error(request, "Email already exists!")
            return redirect('signup')
        
        if len(username)>10:
            messages.error(request, "Username should contain 10 characters!")

        if password != conform:
            messages.error(request, "Passwords didn't match!!")

        if not username.isalnum():
            messages.error(request, "Username must be alpha-numeric!!")
            return redirect('signup')

        
        theuser = User.objects.create_user( username=username , email=email, password=password)
        theuser.fname = fname
        theuser.lname = lname 
        theuser.is_active = False
        theuser.save()

        # for welcome message
        subject = "Welcome to the login website!!"
        message = "Hello "+  theuser.fname + " "+ theuser.lname +" you have registered on the login website\n We have send you a confirmation email, please confirm to activate your account.\n\nThank you for visiting our website "
        from_email = settings.EMAIL_HOST_USER
        messages.success(request , "after from email")
        to_list = [theuser.email]
        send_mail(subject, message, from_email, to_list, fail_silently=True)


        # conformation mail
        current_site = get_current_site(request)
        conf_subject = "Confirm your email @ login website!! "
        conf_message = render_to_string('confirmation.html',
        {'name':theuser.fname, 
        'domain':current_site.domain, 
        'uid':urlsafe_base64_encode(force_bytes(theuser.pk)),
        'token':generate_token.make_token(theuser)
        })
        
        send_mail(conf_subject, conf_message, settings.EMAIL_HOST_USER, [theuser.email], fail_silently=True)

        return redirect('signin') 

    return render(request , "base/signup.html")

def signin(request):

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        theuser = authenticate(username=username, password=password)
        print("the user",theuser)
        if theuser is not None:
            login(request , theuser)
            fname = theuser.fname
            return render(request, "base/index.html", {'fname':fname})
            
        else:
            messages.error(request, "Enter correct inputs.")
            return redirect('signin')

    return render(request , "base/signin.html")

def signout(request):

    logout(request)
    messages.success(request , "Logged out successfully!!!")
    return redirect('home')

def activate(request, uidb64, tokens):
    try:
        uid = force_str(urlsafe_b64decode(uidb64))
        theuser = User.objects.get(pk=uid)

    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        theuser = None

    if theuser is not None and generate_token.check_token(theuser , tokens):
        theuser.is_active = True
        theuser.save()
        login(request,theuser)
        return redirect('home')
    else:
        return render(request, 'activation_failed.html')






