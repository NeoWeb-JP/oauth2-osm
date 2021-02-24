<?php

namespace neowebjp\OAuth2\Client\Provider;

use DOMDocument;
use DOMXPath;
use GuzzleHttp\Exception\BadResponseException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use UnexpectedValueException;

class Osm extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var array|null
     */
    public $scopes = [];

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        return 'https://www.onlinescoutmanager.co.uk/oauth/authorize';
    }

    /**
     * Get access token url to retrieve token
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return 'https://www.onlinescoutmanager.co.uk/oauth/token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return 'https://www.onlinescoutmanager.co.uk/oauth/resource';
    }

    /**
     * Requests and returns the resource owner of given access token.
     *
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $token)
    {
        $response = $this->fetchResourceOwnerDetails($token);

        return $this->createResourceOwner($response, $token);
    }

    /**
     * Sends a request and returns the parsed response.
     *
     * @param  RequestInterface $request
     * @throws IdentityProviderException
     * @return mixed
     */
    public function getParsedResponse(RequestInterface $request)
    {
        try {
            $response = $this->getResponse($request);
        } catch (BadResponseException $e) {
            $response = $e->getResponse();
        }

        $parsed = $this->parseResponse($response);

        $this->checkResponse($response, $parsed);

        return $parsed;
    }

    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        $url = $this->getResourceOwnerDetailsUrl($token);

        $request = $this->getAuthenticatedRequest(self::METHOD_GET, $url, $token);
        $response = "";

        try {
            $response = $this->getParsedResponse($request);
            if (false === is_array($response)) {

                //Only usually triggered when site is being blocked by OSM
                $dom = new DOMDocument();
                $dom->loadHTML(preg_replace( "/\r|\n/", "", $response));

                $xpath = new DOMXpath($dom);
                $title = $xpath->query('//title');
                $result = $xpath->query('//div[@class="section__inner"]/p');

                if ($title->length > 0) {
                   $response = array(
                        "error" => true,
                        "result" => $title[0]->nodeValue . " : " . $result[0]->nodeValue
                   );
                } else {
                    throw new UnexpectedValueException(
                        'Invalid response received from Authorization Server. Expected JSON.'
                    );
                }
            }

        } catch (IdentityProviderException $e) {

        }

        return $response;
    }


    /**
     * Get the default scopes used by this provider.
     *
     * @return array
     */
    protected function getDefaultScopes(): ?array
    {
        return $this->scopes;
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ','
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * Returns all options that are required.
     *
     * @return array
     */
    protected function getRequiredOptions(): array
    {
        return [
            'urlAuthorize',
            'urlAccessToken',
            'urlResourceOwnerDetails',
        ];
    }

    /**
     * Returns all options that can be configured.
     *
     * @return array
     */
    protected function getConfigurableOptions(): array
    {
        return array_merge($this->getRequiredOptions(), [
            'accessTokenMethod',
            'accessTokenResourceOwnerId',
            'scopeSeparator',
            'responseError',
            'responseCode',
            'responseResourceOwnerId',
            'scopes',
        ]);
    }

    /**
     * Check a provider response for errors.
     *
     * @param  ResponseInterface $response
     * @param  array|string $data
     *
     * @throws IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['error'])) {
            $statusCode = $response->getStatusCode();
            $error = $data['error'];
            $errorDescription = (isset($data['error_description']) ? $data['error_description'] : false);
            $errorLink = (isset($data['error_uri']) ? $data['error_uri'] : false);
            throw new IdentityProviderException(
                $statusCode . ' - '
                . ($errorDescription ? $errorDescription : "")
                . ': ' . (is_array($error) ? json_encode($error) : $error)
                . ($errorLink ? ' (see: ' . $errorLink . ')' : ''),
                $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     *
     * @return OsmResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token): OsmResourceOwner
    {
        return new OsmResourceOwner($response);
    }

    /**
     * Returns a prepared request for requesting an access token.
     *
     * @param array $params
     *
     * @return RequestInterface
     */
    protected function getAccessTokenRequest(array $params): RequestInterface
    {
        $request = parent::getAccessTokenRequest($params);
        $uri = $request->getUri()
            ->withUserInfo($this->clientId, $this->clientSecret);
        return $request->withUri($uri);
    }

    public function getAccessToken($grant, array $options = [])
    {
        $grant = $this->verifyGrant($grant);

        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        $request  = $this->getAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {

            //Only usually triggered when site is being blocked by OSM
            $dom = new DOMDocument();
            $dom->loadHTML(preg_replace("/\r|\n/", "", $response));

            $xpath = new DOMXpath($dom);
            $title = $xpath->query('//title');
            $result = $xpath->query('//div[@class="section__inner"]/p');

            if ($title->length > 0) {
                $response = array(
                    "error" => true,
                    "result" => $title[0]->nodeValue . " : " . $result[0]->nodeValue
                );
            } else {
                throw new UnexpectedValueException(
                    'Invalid response received from Authorization Server. Expected JSON.'
                );
            }
        }

        $prepared = $this->prepareAccessTokenResponse($response);
        return $this->createAccessToken($prepared, $grant);
    }
}
