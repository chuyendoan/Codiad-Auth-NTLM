Codiad-Auth-NTLM
================

NTLM authentication for Codiad

**Basic Setup**

- Download archive and extract ```ntlm.class.php``` to your Codiad installation
- Configure ```ntlm.class.php``` to your needs
- Enable external authentification in your ```config.php```

```
define("AUTH_PATH", "ntlm.class.php");
```

**Configuration** 

*Use static user database*

- Set ```ntlm::login(true);``` in ```ntlm.class.php```
- Add your users with plain passwords to $userdb

```
public static $userdb = array('deaks'=>'mypassword');
```

*Use samba backend*

- Set ```ntlm::login(false);``` in ```ntlm.class.php```
- Compile ```verifyntlm.c ``` according to that [tutorial](http://siphon9.net/loune/2010/12/php-ntlm-integration-with-samba/)
- Place it into ```/sbin/```
