Opauth-Ultrareg
=============
[Opauth][1] strategy for Ultrareg authentication.

Implemented based on https://ultrareg.knowit.no

Getting started
----------------
1. Install Opauth-Ultrareg:

   Using git:
   ```bash
   cd path_to_opauth/Strategy
   git clone https://github.com/t1mmen/opauth-ultrareg.git ultrareg
   ```

  Or, using [Composer](https://getcomposer.org/), just add this to your `composer.json`:

   ```bash
   {
       "require": {
           "t1mmen/opauth-ultrareg": "*"
       }
   }
   ```
   Then run `composer install`.


2. Create Ultrareg application at https://api.ultrareg.com/applications

3. Configure Opauth-Ultrareg strategy with at least `Client ID` and `Client Secret`.

4. Direct user to `http://path_to_opauth/ultrareg` to authenticate

Strategy configuration
----------------------

Required parameters:

```php
<?php
'Ultrareg' => array(
	'client_id' => 'YOUR CLIENT ID',
	'client_secret' => 'YOUR CLIENT SECRET'
)
```

License
---------
Opauth-Ultrareg is MIT Licensed
Copyright © 2015 Timm Stokke (http://timm.stokke.me)

[1]: https://github.com/opauth/opauth
