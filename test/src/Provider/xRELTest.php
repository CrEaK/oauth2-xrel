<?php

namespace xREL\OAuth2\Client\Test\Provider;

use GuzzleHttp\Psr7\Response;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use xREL\OAuth2\Client\Provider\xREL;

class xRELTest extends TestCase
{
    protected $provider;

    protected static function getMethod($name)
    {
        $class = new ReflectionClass('xREL\OAuth2\Client\Provider\xREL');
        $method = $class->getMethod($name);
        $method->setAccessible(true);

        return $method;
    }

    protected function setUp(): void
    {
        $this->provider = new xREL([
            'clientId'      => 'mock_client_id',
            'clientSecret'  => 'mock_secret',
            'redirectUri'   => 'none',
        ]);
    }

    private function createJsonResponse($body, $status = 200)
    {
        return new Response($status, ['content-type' => 'application/json'], $body);
    }

    public function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testScopes()
    {
        $options = ['scope' => [uniqid(), uniqid()]];

        $url = $this->provider->getAuthorizationUrl($options);

        $this->assertStringContainsString(urlencode(implode(',', $options['scope'])), $url);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/v2/oauth2/auth', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];
        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/v2/oauth2/token', $uri['path']);
    }

    public function testGetAccessToken()
    {
        $response = $this->createJsonResponse(
            '{"access_token":"mock_access_token","expires_in":3600,"token_type":"bearer","refresh_token":"mock_refresh_token"}'
        );

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertLessThanOrEqual(time() + 3600, $token->getExpires());
        $this->assertGreaterThanOrEqual(time(), $token->getExpires());
        $this->assertEquals('mock_refresh_token', $token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserData()
    {
        $userId = uniqid();
        $name = uniqid();
        $avatar = uniqid();

        $postResponse = $this->createJsonResponse(
            '{"access_token":"mock_access_token","expires_in":3600,"token_type":"bearer","refresh_token":"mock_refresh_token"}'
        );

        $userResponse = $this->createJsonResponse(
            '{"id":"'.$userId.'","name":"'.$name.'","avatar_url":"'.$avatar.'"}'
        );

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals($userId, $user->getId());
        $this->assertEquals($userId, $user->toArray()['id']);
        $this->assertEquals($name, $user->getName());
        $this->assertEquals($name, $user->toArray()['name']);
        $this->assertEquals($avatar, $user->getAvatarUrl());
        $this->assertEquals($avatar, $user->toArray()['avatar_url']);
    }

    public function testExceptionThrownWhenErrorObjectReceived()
    {
        $this->expectException('League\OAuth2\Client\Provider\Exception\IdentityProviderException');

        $error = uniqid();
        $message = uniqid();
        $status = rand(400, 600);

        $postResponse = $this->createJsonResponse(
            '{"access_token":"mock_access_token","expires_in":3600,"token_type":"bearer","refresh_token":"mock_refresh_token"}'
        );

        $userResponse = $this->createJsonResponse(
            '{"error_type":"api","error":"'.$error.'","error_description":"'.$message.'"}',
            $status
        );

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getResourceOwner($token);
    }
}
