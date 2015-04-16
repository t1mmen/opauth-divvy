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

			$response = $this->serverPost($url, $params, null);

			$results = json_decode($response,true);

			if (!empty($results) && !empty($results['access_token'])) {

				$user = $this->userCURL($results['access_token']);

				$this->auth = array(
					'uid' => $user['Name'],
					'info' => array(),
					'credentials' => $results,
					'raw' => $user
				);

				// Scope set = retrieve credentials via API key:
				if (in_array('scope', $this->optionals) && isset($results['api_key'])) {
					$this->auth['credentials'] = $this->getCredentials($url, $results['api_key']);
				}

				// OpAuth expects 'token' as key:
				if (isset($this->auth['credentials']['access_token'])) {
					$this->auth['credentials']['token'] = $this->auth['credentials']['access_token'];
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

				if (isset($this->auth['info']['first_name']) && isset($this->auth['info']['last_name'])) {
					$this->auth['info']['name'] = $this->auth['info']['first_name'].' '.$this->auth['info']['last_name'];
				} else {
					$this->auth['info']['name'] = 'Unknown';
				}

				$this->callback();
			}
			else {
				$error = array(
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => array(
						'response' => $response
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
	 * Queries Ultrareg API via cURL
	 *
	 * We're most likely hitting some sort of header limitation with the token > 800 chars.
	 * So, falling back to cURL for now:
	 *
	 * @param string $access_token
	 * @return array Parsed JSON results
	 */
	private function userCURL($access_token) {

		$ch_subs = curl_init();
		curl_setopt($ch_subs, CURLOPT_URL, 'https://ultrareg.knowit.no/api/identity');
		$headers = array('Authorization: Bearer ' . $access_token);
		curl_setopt($ch_subs, CURLOPT_HTTPHEADER, $headers);

		curl_setopt($ch_subs, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch_subs, CURLOPT_SSL_VERIFYPEER, false);
		$subs_return = curl_exec($ch_subs);
		curl_close($ch_subs);

		if (!empty($subs_return)) {
			return $this->recursiveGetObjectVars(json_decode($subs_return));
		} else {
			$error = array(
				'code' => 'userinfo_error',
				'message' => 'Failed when attempting to query Ultrareg API for user information via cURL',
				'raw' => array(
					'response' => $user,
				)
			);

			$this->errorCallback($error);
		}
	}

	/**
	 * Query Ultrareg API for access token based on user API key
	 * @param  string $api_key
	 * @return array  Parsed JSON results
	 */
	private function getCredentials($url, $api_key) {

		$cred = base64_encode($this->strategy['client_id'].':'.$this->strategy['client_secret']);

		$data = array(
			'grant_type' => 'http://ultrareg.knowit.no/identity/granttype/api_key',
			'redirect_uri' => $this->strategy['redirect_uri']
			'api_key' => $api_key);

		$options['http'] = array(
			'header' => "Authorization: Basic ".$cred."\r\nContent-type: application/x-www-form-urlencoded",
			'method' => 'POST',
			'content' => http_build_query($data, '', '&')
			);

		$credentials = $this->httpRequest($url, $options);

		if (!empty($credentials)) {
			return $this->recursiveGetObjectVars(json_decode($credentials));
		} else {
			$error = array(
				'code' => 'credentials_error',
				'message' => 'Count not retrieve access token based on API key',
				'raw' => array(
					'response' => $credentials,
				)
			);

			$this->errorCallback($error);
		}

	}
}
