<?php

namespace Luchki\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Vkontakte extends AbstractProvider
{

        const VERSION = '3.0.3';

        protected $baseOAuthUri = 'https://id.vk.com';
        protected $baseUri      = 'https://api.vk.com/method';
        protected $version      = '5.199';
        protected $language     = null;

        /**
         * Default scopes used by this provider
         * @link https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/work-with-user-info/scopes
         * @var string[]
         */
        public $scopes = [
                'vkid.personal_info',
        ];

        /**
         * User Field Set
         * @link https://dev.vk.com/ru/reference/objects/user
         * @var string[]
         */
        public $userFields = [
                // -- Basic fields
                'id',
                'first_name',
                'last_name',
                'deactivated',
                'is_closed',
                'can_access_closed',
                // -- Optional fields
                //'about',
                //'activities',
                'bdate',
                //'blacklisted',
                //'blacklisted_by_me',
                //'books',
                //'can_post',
                //'can_see_all_posts',
                //'can_see_audio',
                //'can_send_friend_request',
                //'can_write_private_message',
                //'career',
                'city',
                //'common_count',
                //'connections',
                //'contacts',
                //'counters',
                'country',
                //'crop_photo',
                'domain',
                //'education',
                //'exports',
                //'first_name_abl',
                //'first_name_acc',
                //'first_name_dat',
                //'first_name_gen',
                //'first_name_ins',
                //'first_name_nom',
                //'followers_count',
                'friend_status',
                //'games',
                //'has_mobile',
                'has_photo',
                'home_town',
                //'interests',
                //'is_favorite',
                'is_friend',
                //'is_hidden_from_feed',
                //'is_no_index',
                //'is_verified',
                //'last_name_abl',
                //'last_name_acc',
                //'last_name_dat',
                //'last_name_gen',
                //'last_name_ins',
                //'last_name_nom',
                //'last_seen',
                //'lists',
                'maiden_name',
                //'military',
                //'movies',
                //'music',
                'nickname',
                //'occupation',
                //'online',
                //'personal',
                //'photo_100',
                //'photo_200',
                //'photo_200_orig',
                //'photo_400_orig',
                //'photo_50',
                //'photo_id',
                'photo_max',
                'photo_max_orig',
                //'quotes',
                //'relation',
                //'relatives',
                //'schools',
                'screen_name',
                'sex',
                //'site',
                //'status',
                //'timezone',
                //'trending',
                //'tv',
                //'universities',
                //'verified',
                //'wall_default',
        ];

        /** @var PkceProviderInterface */
        private $pkce_provider;

        public function __construct(array $options = [], array $collaborators = []) {
                parent::__construct($options, $collaborators);

                $pkce_provider = $collaborators['pkceProvider'] ?? null;

                if ($pkce_provider === null) {
                        $this->pkce_provider = new SessionPkceProvider();
                } else {
                        if (!$pkce_provider instanceof PkceProviderInterface) {
                                throw new \LogicException(
                                        'The pkceProvider can be used with ' . PkceProviderInterface::class
                                );
                        }

                        $this->pkce_provider = $pkce_provider;
                }
        }

        /**
         * @param string $language
         */
        public function setLanguage($language) {
                $this->language = (string)$language;

                return $this;
        }

        public function getBaseAuthorizationUrl() {
                return "$this->baseOAuthUri/authorize";
        }

        public function getBaseAccessTokenUrl(array $params) {
                return $this->baseOAuthUri . '/oauth2/auth';
        }

        /**
         * Returns the value, converted using sha256 and encoded in base64
         * @param string $verifier PKCE verifier
         * @return string
         */
        private function code_challenge($verifier) {
                $hash = hash($this->pkce_provider->getAlgoritm(), $verifier, true);

                return rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');
        }

        /**
         * @inheritDoc
         * @link https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/api-description#Zapros-koda-podtverzhdeniya-i-rabota-s-formoj-razresheniya-dostupov-polzovatelya
         */
        protected function getAuthorizationParameters(array $options) {
                $options = parent::getAuthorizationParameters($options);
                // VK OAuth 2.1 PKCE Protocol Challenge
                if (!isset($options['code_challenge'])) {
                        $verifier = $this->pkce_provider->makeVerifier();
                        $options['code_challenge'] = $this->code_challenge($verifier);
                        $options['code_challenge_method'] = $this->pkce_provider->getMethod();
                        $this->pkce_provider->setVerifier($verifier);
                }

                return $options;
        }

        /**
         * Enriches the parameters for the token request with the device identifier
         * @param string[] $options Token request parameters
         * @param string   $key
         */
        private static function _enrich_device_id(array &$options, $key = 'device_id') {
                if (!array_key_exists($key, $options) && array_key_exists($key, $_GET)) {
                        $options[$key] = $_GET[$key];
                }
        }

        /**
         * @inheritDoc
         * @link https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/api-description#Poluchenie-cherez-kod-podtverzhdeniya
         */
        public function getAccessToken($grant, array $options = []) {
                self::_enrich_device_id($options);
                $options['code_verifier'] = $this->pkce_provider->getVerifier();

                return parent::getAccessToken($grant, $options);
        }

        public function getResourceOwnerDetailsUrl(AccessToken $token) {
                $params = [
                        'fields'       => $this->userFields,
                        'access_token' => $token->getToken(),
                        'v'            => $this->version,
                        'lang'         => $this->language,
                ];
                $query = $this->buildQueryString($params);
                $url = "$this->baseUri/users.get?$query";

                return $url;
        }

        /**
         * @inheritDoc
         */
        protected function getDefaultScopes() {
                return is_string($this->scopes)
                        ? explode(' ', $this->scopes)
                        : $this->scopes;
        }

        protected function checkResponse(ResponseInterface $response, $data) {
                // Metadata info
                $contentTypeRaw = $response->getHeader('Content-Type');
                $contentTypeArray = explode(';', reset($contentTypeRaw));
                $contentType = reset($contentTypeArray);
                // Response info
                $responseCode = $response->getStatusCode();
                $responseMessage = $response->getReasonPhrase();
                // Data info
                $error = !empty($data['error'])
                        ? $data['error']
                        : null;
                $errorCode = !empty($error['error_code'])
                        ? $error['error_code']
                        : $responseCode;
                $errorDescription = !empty($data['error_description'])
                        ? $data['error_description']
                        : null;
                $errorMessage = !empty($error['error_msg'])
                        ? $error['error_msg']
                        : $errorDescription;
                $message = $errorMessage
                        ?: $responseMessage;

                // Request/meta validation
                if (399 < $responseCode) {
                        throw new IdentityProviderException($message, $responseCode, $data);
                }

                // Content validation
                if ('application/json' != $contentType) {
                        throw new IdentityProviderException($message, $responseCode, $data);
                }
                if ($error) {
                        throw new IdentityProviderException($errorMessage, $errorCode, $data);
                }
        }

        /**
         * @inheritDoc
         */
        protected function createResourceOwner(array $response, AccessToken $token) {
                $jwt = new IdToken($token);
                $response = reset($response['response']);
                if ($id = $jwt->id()) {
                        $response['id'] = $id;
                }
                if ($email = $jwt->email()) {
                        $response['email'] = $email;
                }
                if ($phone = $jwt->phone()) {
                        $response['phone'] = $phone;
                }

                return new VkontakteUser($response);
        }

        /**
         * @see https://vk.com/dev/users.get
         *
         * @param integer[]        $ids
         * @param AccessToken|null $token Current user if empty
         * @param array            $params
         *
         * @return VkontakteUser[]
         */
        public function usersGet(array $ids = [], AccessToken $token = null, array $params = []) {
                if (empty($ids) && !$token) {
                        throw new \InvalidArgumentException('Some of parameters usersIds OR access_token are required');
                }

                $default = [
                        'user_ids'     => implode(',', $ids),
                        'fields'       => $this->userFields,
                        'access_token' => $token
                                ? $token->getToken()
                                : null,
                        'v'            => $this->version,
                        'lang'         => $this->language,
                ];
                $params = array_merge($default, $params);
                $query = $this->buildQueryString($params);
                $url = "$this->baseUri/users.get?$query";

                $response = $this->getResponse($this->createRequest(static::METHOD_GET, $url, $token, []))['response'];
                $users = !empty($response['items'])
                        ? $response['items']
                        : $response;
                $array2user = function($userData) {
                        return new VkontakteUser($userData);
                };

                return array_map($array2user, $users);
        }

        /**
         * @see https://vk.com/dev/friends.get
         *
         * @param integer          $userId
         * @param AccessToken|null $token
         * @param array            $params
         *
         * @return VkontakteUser[]
         */
        public function friendsGet($userId, AccessToken $token = null, array $params = []) {
                $default = [
                        'user_id'      => $userId,
                        'fields'       => $this->userFields,
                        'access_token' => $token
                                ? $token->getToken()
                                : null,
                        'v'            => $this->version,
                        'lang'         => $this->language,
                ];
                $params = array_merge($default, $params);
                $query = $this->buildQueryString($params);
                $url = "$this->baseUri/friends.get?$query";

                $response = $this->getResponse($this->createRequest(static::METHOD_GET, $url, $token, []))['response'];
                $friends = !empty($response['items'])
                        ? $response['items']
                        : $response;
                $array2friend = function($friendData) {
                        if (is_numeric($friendData)) {
                                $friendData = ['id' => $friendData];
                        }

                        return new VkontakteUser($friendData);
                };

                return array_map($array2friend, $friends);
        }
}
