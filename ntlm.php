<?php

  /*

  php ntlm authentication library
  Version 1.2

  Copyright (c) 2009-2010 Loune Lam

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

  */

  ntlm::login(true);

  class ntlm {

    public static $userdb = array();
    
    public static function login($userdb = true) {
      self::ntlm_unset_auth();
    
      $auth = self::ntlm_prompt("testwebsite", "testdomain", "mycomputer", "testdomain.local", "mycomputer.local", $userdb);
      if ($auth['authenticated']) {
          $_SESSION['user'] = $auth['username'];
      } 
    }
    
    public static function get_ntlm_user_hash($user) {
        return self::ntlm_md4(self::ntlm_utf8_to_utf16le(self::$userdb[strtolower($user)]));
    }

    public static function ntlm_utf8_to_utf16le($str) {
      return iconv('UTF-8', 'UTF-16LE', $str);
    }

    public static function ntlm_md4($s) {
      if (function_exists('mhash'))
        return mhash(MHASH_MD4, $s);
      return pack('H*', hash('md4', $s));
    }

    public static function ntlm_av_pair($type, $utf16) {
      return pack('v', $type).pack('v', strlen($utf16)).$utf16;
    }

    public static function ntlm_field_value($msg, $start, $decode_utf16 = true) {
      $len = (ord($msg[$start+1]) * 256) + ord($msg[$start]);
      $off = (ord($msg[$start+5]) * 256) + ord($msg[$start+4]);
      $result = substr($msg, $off, $len);
      if ($decode_utf16) {
        $result = iconv('UTF-16LE', 'UTF-8', $result);
      }
      return $result;
    }

    public function ntlm_hmac_md5($key, $msg) {
      $blocksize = 64;
      if (strlen($key) > $blocksize)
        $key = pack('H*', md5($key));
      
      $key = str_pad($key, $blocksize, "\0");
      $ipadk = $key ^ str_repeat("\x36", $blocksize);
      $opadk = $key ^ str_repeat("\x5c", $blocksize);
      return pack('H*', md5($opadk.pack('H*', md5($ipadk.$msg))));
    }

    public static function ntlm_get_random_bytes($length) {
      $result = "";
      for ($i = 0; $i < $length; $i++) {
        $result .= chr(rand(0, 255));
      }
      return $result;
    }

    public static function ntlm_get_challenge_msg($msg, $challenge, $targetname, $domain, $computer, $dnsdomain, $dnscomputer) {
      $domain = self::ntlm_field_value($msg, 16);
      $ws = self::ntlm_field_value($msg, 24);
      $tdata = self::ntlm_av_pair(2, self::ntlm_utf8_to_utf16le($domain)).self::ntlm_av_pair(1, self::ntlm_utf8_to_utf16le($computer)).self::ntlm_av_pair(4, self::ntlm_utf8_to_utf16le($dnsdomain)).self::ntlm_av_pair(3, self::ntlm_utf8_to_utf16le($dnscomputer))."\0\0\0\0\0\0\0\0";
      $tname = self::ntlm_utf8_to_utf16le($targetname);

      $msg2 = "NTLMSSP\x00\x02\x00\x00\x00".
        pack('vvV', strlen($tname), strlen($tname), 48). // target name len/alloc/offset
        "\x01\x02\x81\x00". // flags
        $challenge. // challenge
        "\x00\x00\x00\x00\x00\x00\x00\x00". // context
        pack('vvV', strlen($tdata), strlen($tdata), 48 + strlen($tname)). // target info len/alloc/offset
        $tname.$tdata;
      return $msg2;
    }

    public static function ntlm_verify_hash_smb($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob) {
      $cmd = bin2hex($challenge)." ".bin2hex(self::ntlm_utf8_to_utf16le(strtoupper($user)))." ".bin2hex(self::ntlm_utf8_to_utf16le($domain))." ".bin2hex(self::ntlm_utf8_to_utf16le($workstation))." ".bin2hex($clientblobhash)." ".bin2hex($clientblob);

      return (`/sbin/verifyntlm $cmd` == "1\n");
    }

    public static function ntlm_verify_hash($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob) {

      $md4hash = self::get_ntlm_user_hash($user);
      if (!$md4hash)
        return false;
      $ntlmv2hash = self::ntlm_hmac_md5($md4hash, self::ntlm_utf8_to_utf16le(strtoupper($user).$domain));
      $blobhash = self::ntlm_hmac_md5($ntlmv2hash, $challenge.$clientblob);

      return ($blobhash == $clientblobhash);
    }

    public static function ntlm_parse_response_msg($msg, $challenge, $ntlm_verify_hash_callback) {
      $user = self::ntlm_field_value($msg, 36);
      $domain = self::ntlm_field_value($msg, 28);
      $workstation = self::ntlm_field_value($msg, 44);
      $ntlmresponse = self::ntlm_field_value($msg, 20, false);
      $clientblob = substr($ntlmresponse, 16);
      $clientblobhash = substr($ntlmresponse, 0, 16);

      if (substr($clientblob, 0, 8) != "\x01\x01\x00\x00\x00\x00\x00\x00") {
        return array('authenticated' => false, 'error' => 'NTLMv2 response required. Please force your client to use NTLMv2.');
      }
      
      if($ntlm_verify_hash_callback) {
        if (!self::ntlm_verify_hash($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob))
          return array('authenticated' => false, 'error' => 'Incorrect username or password.', 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
      } else {
        if (!self::ntlm_verify_hash_smb($challenge, $user, $domain, $workstation, $clientblobhash, $clientblob))
          return array('authenticated' => false, 'error' => 'Incorrect username or password.', 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
      }
      return array('authenticated' => true, 'username' => $user, 'domain' => $domain, 'workstation' => $workstation);
    }

    public static function ntlm_unset_auth() {
      unset ($_SESSION['_ntlm_auth']);
    }

    public static function ntlm_prompt($targetname, $domain, $computer, $dnsdomain, $dnscomputer, $ntlm_verify_hash_callback = true, $failmsg = "<h1>Authentication Required</h1>") {

      $auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : null;
      if ($auth_header == null && function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
        $auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
      }
      
      if (isset($_SESSION['_ntlm_auth']))
        return $_SESSION['_ntlm_auth'];
      
      if (!$auth_header) {
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: NTLM');
        print $failmsg;
        exit;
      }

      if (substr($auth_header,0,5) == 'NTLM ') {
        $msg = base64_decode(substr($auth_header, 5));
        if (substr($msg, 0, 8) != "NTLMSSP\x00") {
          unset($_SESSION['_ntlm_post_data']);
          die('NTLM error header not recognised');
        }

        if ($msg[8] == "\x01") {
          $_SESSION['_ntlm_server_challenge'] = self::ntlm_get_random_bytes(8);
          header('HTTP/1.1 401 Unauthorized');
          $msg2 = self::ntlm_get_challenge_msg($msg, $_SESSION['_ntlm_server_challenge'], $targetname, $domain, $computer, $dnsdomain, $dnscomputer);
          header('WWW-Authenticate: NTLM '.trim(base64_encode($msg2)));
          exit;
        }
        else if ($msg[8] == "\x03") {
          $auth = self::ntlm_parse_response_msg($msg, $_SESSION['_ntlm_server_challenge'], $ntlm_verify_hash_callback);
          unset($_SESSION['_ntlm_server_challenge']);
          
          if (!$auth['authenticated']) {
            header('HTTP/1.1 401 Unauthorized');
            header('WWW-Authenticate: NTLM');
            print $failmsg;
            print $auth['error'];
            exit;
          }
                
          $_SESSION['_ntlm_auth'] = $auth;
          return $auth;
        }
      }
    }
  }

?>
