<?php
namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\Auth\RegisterController;


Route::prefix('v1')->group(function(){
    Route::post('/send-message', [TokoKelontongController::class, 'contact_message']);
    Route::post('/newsletter', [TokoKelontongController::class, 'newsletter']);
    Route::get('/location', [TokoKelontongController::class, 'location']);
    Route::get('/list-visitor', [TokoKelontongController::class, 'visitor_list']);
    Route::get('/user-list', [TokoKelontongController::class, 'user_lists']);
    Route::get('/user-has-online', [TokoKelontongController::class, 'user_has_online']);
    Route::get('/detect-ip', [TokoKelontongController::class, 'detect_ip']);

    Route::middleware('auth:api')->get('/user', function (Request $request) {
        return $request->user();
    });

    Route::post('/register', [RegisterController::class, 'register']);
    Route::post('/login', [LoginController::class, 'login']);
    Route::post('/logout', [LoginController::class, 'logout'])->middleware('auth:api');

    Route::get('/auth/redirect/{provider}', [LoginController::class, 'redirectToProvider']);

    Route::get('/auth/{provider}/callback', [LoginController::class, 'handleProviderCallback']);

});