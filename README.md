Opauth-Divvy
=============
[Opauth][1] strategy for Divvy authentication. 

Implemented based on https://www.divvy.no

Getting started
----------------
0. Make sure cURL is enabled (required due to header size issues using Opauth's transport method)

1. Install Opauth-Divvy:

   Using git:
   ```bash
   cd path_to_opauth/Strategy
   git clone https://github.com/t1mmen/opauth-divvy.git divvy
   ```

  Or, using [Composer](https://getcomposer.org/), just add this to your `composer.json`:

   ```bash
   {
       "require": {
           "t1mmen/opauth-divvy": "*"
       }
   }
   ```
   Then run `composer install`.


2. Create Divvy application at https://divvy.knowit.no/account

3. Configure Opauth-Divvy strategy with at least `Client ID` and `Client Secret`.

4. Direct user to `http://path_to_opauth/divvy` to authenticate

Strategy configuration
----------------------

Required parameters:

```php
<?php
'Divvy' => array(
	'client_id' => 'YOUR CLIENT ID',
	'client_secret' => 'YOUR CLIENT SECRET'
)
```

License
---------
Opauth-Divvy is MIT Licensed
Copyright © 2015 Timm Stokke (http://timm.stokke.me)

[1]: https://github.com/opauth/opauth
