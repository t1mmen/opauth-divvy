<?php
/**
 * Ultrareg strategy for Opauth
 *
 * Based on work by U-Zyn Chua (http://uzyn.com)
 *
 * More information on Opauth: http://opauth.org
 *
 * @copyright    Copyright © 2015 Timm Stokke (http://timm.stokke.me)
 * @link         http://opauth.org
 * @package      Opauth.BasecampStrategy
 * @license      MIT License
 */


/**
 * Ultrareg strategy for Opauth
 *
 * @package			Opauth.Ultrareg
 */
class UltraregStrategy extends OpauthStrategy {

	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('client_id', 'client_secret');

	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = array('redirect_uri', 'scope', 'state');

	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'post');
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}oauth2callback'
	);

	/**
	 * Auth request
	 */
	public function request() {
		$url = 'https://ultrareg.knowit.no/oauth/authorize';
		$params = array(
			'response_type' => 'code',
			'client_id' => $this->strategy['client_id'],
			'redirect_uri' => $this->strategy['redirect_uri']
		);


		foreach ($this->optionals as $key) {
			if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
		}

		$this->clientGet($url, $params);
	}

	/**
	 * Internal callback, after OAuth
	 */
	public function oauth2callback() {

		if (array_key_exists('code', $_GET) && !empty($_GET['code'])) {
			$code = $_GET['code'];
			$url = 'https://ultrareg.knowit.no/oauth/token';

			$params = array(
				'code' => $code,
				'grant_type' => 'authorization_code',
				'client_id' => $this->strategy['client_id'],
				'client_secret' => $this->strategy['client_secret'],
				'redirect_uri' => $this->strategy['redirect_uri'],
			);

			if (!empty($this->strategy['state'])) $params['state'] = $this->strategy['state'];

			$response = $this->serverPost($url, $params, null, $headers);

			$results = json_decode($response,true);

			if (!empty($results) && !empty($results['access_token'])) {

				$user = $this->user($results['access_token']);

				$this->auth = array(
					'uid' => $user['Name'],
					'info' => array(),
					'credentials' => $results,
					'raw' => $user
				);

				// Scope set = retrieve API key instead of tokens
				if (in_array('scope', $this->optionals) && isset($results['api_key'])) {
						$this->auth['credentials'] = ['token' => $results['api_key']];
				}

				// Extract Claims
				foreach ($user['Claims'] as $claim) {
					switch ($claim['Type']) {
						case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname':
							$this->auth['info']['first_name'] = $claim['Value'];
							break;
						case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname':
							$this->auth['info']['last_name'] = $claim['Value'];
							break;
						case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
							$this->auth['info']['email'] = $claim['Value'];
							break;
						case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name':
							$this->auth['info']['nickname'] = $claim['Value'];
							break;
						case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone':
							$this->auth['info']['phone'] = $claim['Value'];
							break;
					}
				}

				$this->auth['info']['name'] = $this->auth['info']['first_name'].' '.$this->auth['info']['last_name'];

				$this->callback();
			}
			else {
				$error = array(
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => array(
						'response' => $response,
						'headers' => $headers
					)
				);

				$this->errorCallback($error);
			}
		}
		else {
			$error = array(
				'code' => 'oauth2callback_error',
				'raw' => $_GET
			);

			$this->errorCallback($error);
		}
	}

	/**
	 * Queries Ultrareg API for user info
	 *
	 * @param string $access_token
	 * @return array Parsed JSON results
	 */
	private function user($access_token) {

		$options['http']['header'] = 'Authorization: Bearer '.$access_token;

		$user = $this->serverGet('https://ultrareg.knowit.no/api/identity', [], $options);

		if (!empty($user)) {
			return $this->recursiveGetObjectVars(json_decode($user));
		} else {
			$error = array(
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query Ultrareg API for user information',
				'raw' => array(
					'response' => $user,
					'headers' => $headers
				)
			);

			$this->errorCallback($error);
		}
	}
}
