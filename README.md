Codiad-Auth-NTLM
================

NTLM authentication for Codiad

**Basic Setup**

- Download archive and extract ```ntlm.class.php``` to your Codiad installation
- Configure ```ntlm.class.php``` to your needs
- Enable external authentification in your ```config.php``` (To be safe for updating, move it to your ```data``` folder)

```
define("AUTH_PATH", "data/ntlm.class.php");
```

**Configuration** 

*Use static user database*

- Set ```ntlm::login(true);``` in ```ntlm.class.php```
- Add your users with plain passwords to $userdb

```
public static $userdb = array('daeks'=>'mypassword');
```

*Use samba backend*

- Set ```ntlm::login(false);``` in ```ntlm.class.php```
- Compile ```verifyntlm.c ``` according to that [tutorial](http://siphon9.net/loune/2010/12/php-ntlm-integration-with-samba/)
- Place it into ```/sbin/```


**Excerpt of the Installation Tutorial**

You may need to modify PDBEDIT_PATH in verifyntlm.c to point to where pdbedit is if it’s not at /usr/bin/pdbedit
Login as root (or add sudo in front) to compile and set the sticky bit:

```
gcc verifyntlm.c -lssl -o verifyntlm
chown root verifyntlm
chmod u=rwxs,g=x,o=x verifyntlm
```

Move the binary to a location such as /sbin/

```
mv verifyntlm /sbin
```

If you put the binary somewhere else, please modify $ntlm_verifyntlmpath in ntlm.class.php.
