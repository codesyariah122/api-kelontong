<?php

namespace App\Http\Controllers\Auth\Social;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Laravel\Socialite\Facades\Socialite;
use File;
use App\Models\User;
use App\Models\Notification;
use App\Events\NotificationEvent;

class GoogleAuthController extends Controller
{
    public function loginWithGoogle($service)
    {
        return Socialite::driver($service)->redirect();
    }

    public function callbackFromGoogle()
    {
        try {
            $user = Socialite::driver('google')->stateless()->user();
            // dd($user);

            $is_user = User::where('email', $user->getEmail())->first();

            if(!$is_user){
                $saveUser = new User;
                $saveUser->google_id = $user->getId();
                $saveUser->name = $user->getName();
                $saveUser->email = $user->getEmail();
                $saveUser->g_avatar = $user->getAvatar();
                $saveUser->password = Hash::make($user->getName().'@'.$user->getId());
                $saveUser->save();
            }else{
                $saveUser = User::where('email',  $user->getEmail())->update([
                    'google_id' => $user->getId()
                ]);
                $saveUser = User::where('email', $user->getEmail())->first();
            }

            $event_context = [
                'notif' => true,
                'message' => $user->getName()." Sedang Login !",
                'name' => 'login'
            ];

            $new_notification = new Notification;
            $new_notification->name="login-google";
            $new_notification->content=$event_context['message'];
            $new_notification->save();

            broadcast(new NotificationEvent($event_context));
            
            $user_login = User::where('email', $user->getEmail())->first();

            return response()->json([
                'success' => true,
                'message' => "{$user->getName()}, login with google",
                'data' => $saveUser
            ]);
            return redirect(env('FRONTEND_APP'));

        } catch (\Throwable $th) {
            throw $th;
        }
    }
    
}
