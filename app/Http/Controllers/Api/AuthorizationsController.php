<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\Api\WeappAuthorizationRequest;
use App\Models\User;
use Illuminate\Support\Arr;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthenticationException;
use App\Http\Requests\Api\AuthorizationRequest;
use App\Http\Requests\Api\SocialAuthorizationRequest;

class AuthorizationsController extends Controller
{
    public function store(AuthorizationRequest $request)
    {
        $username = $request->username;

        filter_var($username, FILTER_VALIDATE_EMAIL) ?
            $credentials['email'] = $username :
            $credentials['phone'] = $username;

        $credentials['password'] = $request->password;

        if (!$token = \Auth::guard('api')->attempt($credentials)) {
            throw new AuthenticationException(trans('auth.failed'));
        }

        return $this->respondWithToken($token)->setStatusCode(201);
    }

    public function socialStore($type, SocialAuthorizationRequest $request)
    {
        $driver = \Socialite::driver($type);

        try {
            if ($code = $request->code) {
                $response = $driver->getAccessTokenResponse($code);
                $token = Arr::get($response, 'access_token');
            } else {
                $token = $request->access_token;

                if ($type == 'weixin') {
                    $driver->setOpenId($request->openid);
                }
            }

            $oauthUser = $driver->userFromToken($token);
        } catch (\Exception $e) {
            throw new AuthenticationException('参数错误，未获取用户信息');
        }

        switch ($type) {
        case 'weixin':
            $unionid = $oauthUser->offsetExists('unionid') ? $oauthUser->offsetGet('unionid') : null;

            if ($unionid) {
                $user = User::where('weixin_unionid', $unionid)->first();
            } else {
                $user = User::where('weixin_openid', $oauthUser->getId())->first();
            }

            // 没有用户，默认创建一个用户
            if (!$user) {
                $user = User::create([
                    'name' => $oauthUser->getNickname(),
                    'avatar' => $oauthUser->getAvatar(),
                    'weixin_openid' => $oauthUser->getId(),
                    'weixin_unionid' => $unionid,
                ]);
            }

            break;
        }

        $token= auth('api')->login($user);

        return $this->respondWithToken($token)->setStatusCode(201);
    }

    public function update()
    {
        $token = auth('api')->refresh();
        return $this->respondWithToken($token);
    }

    public function destroy()
    {
        auth('api')->logout();
        return response(null, 204);
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }

    public function weappStore(WeappAuthorizationRequest $request)
    {

        $code = $request->code;//从前端传过来的code只能使用一次

        // 根据 code 获取微信 openid 和 session_key
        $miniProgram = \EasyWeChat::miniProgram();
        $data = $miniProgram->auth->session($code);//$data返回的结构：["session_key" => "7T3mk6/X+IeJXNcPJshW2Q==", "openid" => "oZpZe5fzEJhqvP8mdGgo0goQr9ns",];

        // 如果结果错误，说明 code 已过期或不正确，返回 401 错误
        if (isset($data['errcode'])) {
            throw new AuthenticationException('code 不正确');
        }

        $user = User::where('weapp_openid', $data['openid'])->first();// 找到 openid 对应的用户
        $attributes['weixin_session_key'] = $data['session_key'];

        if (!$user) {//如果未找到对应的用户，则需要提交用户名和密码进行用户绑定
            if (!$request->username) throw new AuthenticationException('用户不存在');
            $username = $request->username;
            $password = $request->password;

            filter_var($username, FILTER_VALIDATE_EMAIL) ? $credentials['email'] = $username : $credentials['phone'] = $username;

            $credentials['password'] = $password;

            if (!auth('api')->once($credentials)) throw new AuthenticationException('用户名或密码错误');// 验证用户名和密码是否正确

            $user = auth('api')->getUser();// 获取对应的用户
            $attributes['weapp_openid'] = $data['openid'];
        }

        $user->update($attributes);// 更新用户数据
        $token = auth('api')->login($user);// 为当前用户创建 JWT

        return $this->respondWithToken($token)->setStatusCode(201);
    }
}
