### Toko Kelontong API

#### Create "personal access" and "password grant" clients which will be used to generate access tokens:
```bash
$ php artisan passport:install
```
### Install passport config
```
$ php artisan passport:keys
$ php artisan vendor:publish --tag=passport-config
$ php artisan vendor:publish --tag=passport-migrations
```

#### Login via google oauth  
<img src="https://raw.githubusercontent.com/codesyariah122/kelontong-api/main/docs/login_google1.png"/>  

<img src="https://raw.githubusercontent.com/codesyariah122/kelontong-api/main/docs/login_google2.png"/>  

### CLient Login Via Google  
https://user-images.githubusercontent.com/13291805/185102320-08a83c4f-6250-4a42-a0f2-dcfb5b042f82.mp4
