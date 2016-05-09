/**
 * Divvy strategy for Opauth
 *
 * @package     Opauth.Divvy
 */
class DivvyStrategy extends OpauthStrategy {

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
    $urlBase = (isset($this->strategy['baseUrl'])) ? $this->strategy['baseUrl'] : 'https://www.divvy.no';
    $url = $urlBase.'/oauth/authorize';

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
      $urlBase = (isset($this->strategy['baseUrl'])) ? $this->strategy['baseUrl'] : 'https://www.divvy.no';
      $url = $urlBase.'/oauth/token';

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
          'uid' => $user['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'],
          'info' => array(),
          'credentials' => $results,
          'raw' => $user
        );

        // Scope set = retrieve credentials via API key:
        if (in_array('scope', $this->optionals) && isset($results['api_key'])) {
          $this->auth['credentials'] = $this->getCredentials($url, $results['api_key']);
        }

        // OpAuth expects 'token' as key:
        if (isset($results['access_token'])) {
          $this->auth['credentials']['token'] = $results['access_token'];
        }

        // Extract Claims
        foreach ($user as $key => $claim) {
          switch ($key) {
            case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname':
              $this->auth['info']['first_name'] = $claim;
              break;
            case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname':
              $this->auth['info']['last_name'] = $claim;
              break;
            case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress':
              $this->auth['info']['email'] = $claim;
              break;
            case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier':
              $this->auth['info']['nickname'] = $claim;
              break;
            case 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone':
              $this->auth['info']['phone'] = $claim;
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
   * Queries Divvy API via cURL
   *
   * We're most likely hitting some sort of header limitation with the token > 800 chars.
   * So, falling back to cURL for now:
   *
   * @param string $access_token
   * @return array Parsed JSON results
   */
  private function userCURL($access_token) {

    $urlBase = (isset($this->strategy['baseUrl'])) ? $this->strategy['baseUrl'] : 'https://www.divvy.no';
    $url = $urlBase.'/openid/userinfo';

    $ch_subs = curl_init();
    curl_setopt($ch_subs, CURLOPT_URL, $url);
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
        'message' => 'Failed when attempting to query Diivy API for user information via cURL',
        'raw' => array(
          'response' => $user,
        )
      );

      $this->errorCallback($error);
    }
  }

  /**
   * Query Divvy API for access token based on API key
   * @param  string $access_token
   * @return array  Parsed JSON results
   */
  private function getCredentials($url, $access_token) {

    $cred = base64_encode($this->strategy['client_id'].':'.$this->strategy['client_secret']);

    $data = array(
      'grant_type' => 'http://www.divvy.no/identity/granttype/api_key',
      'redirect_uri' => $this->strategy['redirect_uri'],
      'api_key' => $access_token);

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
