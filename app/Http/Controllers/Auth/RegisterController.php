<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;
use libphonenumber\PhoneNumberType;
use Propaganistas\LaravelPhone\Rules\Phone as Rule;
use Propaganistas\LaravelPhone\Exceptions\InvalidParameterException;
use Carbon\Carbon;
use App\Events\NotificationEvent;
use App\Models\User;
use App\Models\Profile;

class RegisterController extends Controller
{
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

    public function register(Request $request)
    {
        try{
            $validator = Validator::make($request->all(), [
                'name'      => 'required',
                'email'     => 'required|email|unique:users',
                // 'phone'     =>  ['field' => 'phone:mobile,ID'],
                'password'  => 'required|min:8|confirmed'
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 400);
            }

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

            $user = User::create([
                'name'      => $request->name,
                'email'     => $request->email,
                'phone'     => $request->phone,
                'ip_address' => $ip_address,
                'password'  => Hash::make($request->password),
            ]);

            $profile = new Profile;
            $profile->longitude = $locator['longitude'];
            $profile->latitude = $locator['latitude'];
            $profile->post_code = $locator['zip'];
            $profile->save();
            $profile_id = $profile->id;

            $user->profiles()->sync($profile_id);

            $data_event = [
                'new_user' => true,
                'message' => "{$user->name}, baru saja mendaftar",
                'data' => $user
            ];
            $user_profile_data = User::with('profiles')->findOrFail($user->id);

            broadcast(new NotificationEvent($data_event));

            return response()->json([
                'success' => true,
                'message' => 'Register Success!',
                'data'    => $user_profile_data  
            ]);

        }catch(Exception $e){
            return response()->json([
                'message' => "Error fetch contact message : {$e->getMessage()}"
            ], 401);
        }
    }
}
