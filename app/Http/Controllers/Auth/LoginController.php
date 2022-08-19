<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as ProviderUser;
use Carbon\Carbon;
use App\Models\User;
use App\Models\Profile;
use App\Events\NotificationEvent;

class LoginController extends Controller
{
    public const PROVIDERS = ['google'];
    public const SUCCESS = 200;
    public const FORBIDDEN = 403;
    public const UNAUTHORIZED = 401;
    public const NOT_FOUND = 404;
    public const NOT_ALLOWED = 405;
    public const UNPROCESSABLE = 422;
    public const SERVER_ERROR = 500;
    public const BAD_REQUEST = 400;
    public const VALIDATION_ERROR = 252;

    public function sendResponse($result = [], $message = NULL)
    {
        $response = [
            'success' => true,
            'data'    => $result,
            'message' => $message,
        ];

        return response()->json($response, self::SUCCESS);
    }

    /**
     * success response method.
     *
     * @param  str  $message
     * @return \Illuminate\Http\Response
     */
    public function respondWithMessage($message = NULL) {
        return response()->json(['success' => true,'message' => $message], self::SUCCESS);
    }

    /**
     * error response method.
     *
     * @param  int  $code
     * @param  str  $error
     * @param  array  $errorMessages
     * @return \Illuminate\Http\Response
     */
    public function sendError($code = NULL, $error = NULL, $errorMessages = [])
    {
        $response['success'] = false;

        switch ($code) {
            case self::UNAUTHORIZED:
            $response['message'] = 'Unauthorized';
            break;
            case self::FORBIDDEN:
            $response['message'] = 'Forbidden';
            break;
            case self::NOT_FOUND:
            $response['message'] = 'Not Found.';
            break;
            case self::NOT_ALLOWED:
            $response['message'] = 'Method Not Allowed.';
            break;
            case self::BAD_REQUEST:
            $response['message'] = 'Bad Request.';
            break;
            case self::UNPROCESSABLE:
            $response['message'] = 'Unprocessable Entity.';
            break;
            case self::SERVER_ERROR:
            $response['message'] = 'Whoops, looks like something went wrong.';
            break;
            case self::VALIDATION_ERROR:
            $response['message'] = 'Validation Error.';
            break;
            default:
            $response['message'] = 'Whoops, looks like something went wrong.';
            break;
        }

        $response['message'] = $error?$error:$response['message'];
        if(!empty($errorMessages)){
            $response['errors'] = $errorMessages;
        }

        return response()->json($response, $code);
    }

    public function getIp(){
        foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key){
            if (array_key_exists($key, $_SERVER) === true){
                foreach (explode(',', $_SERVER[$key]) as $ip){
                    $ip = trim($ip); // just to be safe
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false){
                        return $ip;
                    }
                }
            }
        }
        return request()->ip(); 
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required'
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = User::where('email', $request->email)->first();

        $big_data_key = env('API_KEY_BIG_DATA');
        $api_ip_key = env('API_KEY_IP_API');

        $ip_address = $this->getIp();

        if($ip_address === "172.19.0.1"){
            $ip_address = "103.139.10.159";
        }else {
            $ip_address = $ip_address;
        }

        $userDetect = Http::get("https://api.bigdatacloud.net/data/timezone-by-ip?ip={$ip_address}&key={$big_data_key}")->json();
        
        $locator = Http::get("http://api.ipapi.com/{$ip_address}?access_key={$api_ip_key}")->json();

        $current = Carbon::now()->setTimezone($userDetect['ianaTimeId']);

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'account not registered, please register first Or Sign in with Google !',
            ]);
        }else{
            if($user['google_id']){
                return response()->json([
                    'failed' => true,
                    'message' => "{$user['email']}, telah terdaftar menggunakan akun {$user['provider_name']}, silahkan login menggunakan sign in with google."
                ]);
            }else{
                if(!Hash::check($request->password, $user->password)){
                    return response()->json([
                        'success' => false,
                        'message' => 'Login Failed! / Email Or Password Failed',
                    ]);
                }

                $user->login = 1;
                $user->ip_address = $ip_address;
                $user->last_login = $current;
                $user->save();

                $user_profile_data = User::with('profiles')->findOrFail($user->id);

                $profile = Profile::find($user_profile_data['profiles'][0]['id'])->first();

                $profile->longitude = $locator['longitude'];
                $profile->latitude = $locator['latitude'];
                $profile->post_code = $locator['zip'];
                $profile->save();

                $user_profile_data = User::with('profiles')->findOrFail($user->id);

                $data_event = [
                    'notif' => "{$user->name}, berhasil login",
                    'login' => true,
                    'last_login' => $user->last_login,
                    'token' => $user->createToken(env('API_AUTH_TOKEN_PASSPORT'))->accessToken
                ];


                $event = broadcast(new NotificationEvent($data_event));

                return response()->json([
                    'success' => true,
                    'message' => 'Login Success!',
                    'data'    => $user_profile_data,
                    'token'   => $user->createToken(env('API_AUTH_TOKEN_PASSPORT'))->accessToken    
                ]);
            }
        }

    }

    public function logout(Request $request)
    {
        $id =  $request->id;
        $user = User::findOrFail($id);
        $user->login = 0;
        $user->ip_address = NULL;
        $user->save();

        $removeToken = $request->user()->tokens()->delete();

        if($removeToken) {
            return response()->json([
                'success' => true,
                'message' => 'Logout Success!',  
            ]);
        }
    }

    private function respondWithToken($token) {
        $success['token'] =  $token;
        $success['access_type'] = 'bearer';
        $success['expires_in'] = now()->addDays(15);

        return $this->sendResponse($success, 'Login successfully.');
    }

    public function redirectToProvider($provider)
    {
        if(!in_array($provider, self::PROVIDERS)){
            return $this->sendError(self::NOT_FOUND); 
        }

        $success['provider_redirect'] = Socialite::driver($provider)->stateless()->redirect()->getTargetUrl();

        return $this->sendResponse($success, "Provider '".$provider."' redirect url.");
    }

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function handleProviderCallback($provider)
    {

        if(!in_array($provider, self::PROVIDERS)){
            return $this->sendError(self::NOT_FOUND);
        }

        try {
            $providerUser = Socialite::driver($provider)->stateless()->user();

            if ($providerUser) {

                $user = User::where('provider_name', $provider)
                ->where('google_id', $providerUser->getId())
                ->first();

                $big_data_key = env('API_KEY_BIG_DATA');
                $api_ip_key = env('API_KEY_IP_API');

                $ip_address = $this->getIp();

                if($ip_address === "172.19.0.1"){
                    $ip_address = "103.139.10.159";
                }else {
                    $ip_address = $ip_address;
                }

                $userDetect = Http::get("https://api.bigdatacloud.net/data/timezone-by-ip?ip={$ip_address}&key={$big_data_key}")->json();
                $current = Carbon::now()->setTimezone($userDetect['ianaTimeId']);

                $locator = Http::get("http://api.ipapi.com/{$ip_address}?access_key={$api_ip_key}")->json();

                if (!$user) {
                    $newuser = new User;
                    $newuser->google_id = $providerUser->getId();
                    $newuser->provider_name = $provider;
                    $newuser->login = 1;
                    $newuser->name = $providerUser->getName();
                    $newuser->email = $providerUser->getEmail();
                    $newuser->g_avatar = $providerUser->getAvatar();
                    $newuser->password = Hash::make($providerUser->getName().'@'.$providerUser->getId());
                    $newuser->last_login = $current;
                    $newuser->ip_address = $ip_address;
                    $newuser->save();

                    $profile = new Profile;
                    $profile->longitude = $locator['longitude'];
                    $profile->latitude = $locator['latitude'];
                    $profile->post_code = $locator['zip'];
                    $profile->save();
                    $profile_id = $profile->id;

                    $newuser->profiles()->sync($profile_id);
                    
                    $token = $newuser->createToken(env('API_AUTH_TOKEN_PASSPORT'))->accessToken; 

                    $data_event = [
                        'login' => true,
                        'notif' => "{$newuser->name} berhasil login",
                        'last_login' => $newuser->last_login,
                        'token' => $token
                    ];

                    $event = broadcast(new NotificationEvent($data_event));

                    // return $this->respondWithToken($token);
                    return redirect(env('FRONTEND_APP').'/auth/success?access_token='.$token);
                }


                $user->login = 1;
                $user->last_login = $current;
                $user->ip_address = $ip_address;
                $user->save();

                $user_profile_data = User::with('profiles')->findOrFail($user->id);

                $profile = Profile::find($user_profile_data['profiles'][0]['id'])->first();

                $profile->longitude = $locator['longitude'];
                $profile->latitude = $locator['latitude'];
                $profile->post_code = $locator['zip'];
                $profile->save();

                $token = $user->createToken(env('API_AUTH_TOKEN_PASSPORT'))->accessToken;

                $data_event = [
                    'login' => true,
                    'notif' => "{$user->name} berhasil login",
                    'last_login' => $user->last_login,
                    'token' => $token
                ];


                $event = broadcast(new NotificationEvent($data_event));


                // return $this->respondWithToken($token);
                return redirect(env('FRONTEND_APP').'/auth/success?access_token='.$token);
            }

        } catch (Exception $exception) {
            return $this->sendError(self::UNAUTHORIZED, null, ['error'=>$e->getMessage()]);
        }        
    }

}
