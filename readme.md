# php_cryptopro_csp
## Crypto pro microservice
https://github.com/dbfun/cryptopro



### Get info for js api
https://docs.cryptopro.ru/cades/plugin/plugin-samples/plugin-samples-sign-detached
https://github.com/pavenkostanislav/ShowingInstaledCertificatList/blob/master/GetingCertificatesListA2Beta16/Scripts/async-crypto.es6.js
https://www.jsdelivr.com/package/npm/cadesplugin-crypto-pro-api



### Runing

  Run container for test auth
```console
$ docker run -it -d --rm -p 8095:8080 --name cryptopro required/cryptopro
```


## Install packages for debug
apt-get update && apt-get install -y procps iproute2 


install certs

мост инфо
http://most-info.ru/public/ca_mostinfo_gost12_2020.crt
минкомсвязь
http://reestr-pki.ru/cdp/guc_gost12.crt
УФК
http://perm.roskazna.ru/upload/iblock/a51/sertifikat-uts-fk-2020.cer

```BASH
 docker cp ./ca_mostinfo_gost12.crt php-ip2u-laravel_cryptopro_1:/tmp
 docker cp ./guc_gost12.crt php-ip2u-laravel_cryptopro_1:/tmp
 docker cp ./sertifikat-uts-fk-2020.cer php-ip2u-laravel_cryptopro_1:/tmp

docker exec -it cryptopro bash


#-- root certificate
certmgr -inst -store uROOT -file  ./guc_gost12.crt
certmgr -inst -store uROOT -file  ./guc_gost12.crt
#-- CA certificate
certmgr -inst -store uCA -file  ./sertifikat-uts-fk-2020.cer
certmgr -inst -store uCA -file  ./ca_mostinfo_gost12_2020.crt


cryptcp -verify -norev -f "sign.sig" "sign.sig.desig"
```

-- check health
 curl -sS localhost:8080/healthcheck | jq .

-- check from HTTP
curl -sS -X POST --data-binary @- "http://localhost:8080/verify" < test_sign_mostinfo.sig | jq .

-- check deattached sign    - with multiple files and updated process
curl -sS -X POST -F "dataInBase64=@./1_txt.base64" -F "sSignedMessage=@./1_p7s.base64" "http://localhost:8080/verifyd" | jq .

-- check by cmd line
cryptcp -verify -f ./test_sign_mostinfo.bin ./test_sign_mostinfo.bin
-- decode
cryptcp -verify  -start  ./test_sign_mostinfo.bin -f ./test_sign_mostinfo.bin  test.out


CSP - working
serial 04AEEA81008BAC629A422A6A6871A0F6E0

see in licence.txt
docker-compose exec cryptopro cpconfig -license -set

before 08.12.2020
after 28.12.2021




add to /public/route ->
$app->post('/verifyd', \App\Controller::class . ':verifyd');


add to www/app/Controller.php
  public function verifyd(Request $request, Response $response, array $args)
  {
    $uploadedFiles = $request->getUploadedFiles();
    // {"dataInBase64":{"file":"\/tmp\/phprFtahK"},"sSignedMessage":{"file":"\/tmp\/phpT0cAlQ"}}
    if (empty($uploadedFiles['dataInBase64']) or empty($uploadedFiles['sSignedMessage']) ) {
                throw new Exception('Expected a sSignedMessage and dataInBase64 in base64');
    }

    $sSignedMessagef = $uploadedFiles['sSignedMessage'];
    if ($sSignedMessagef->getError() === UPLOAD_ERR_OK) {
        $uploadFileName = $sSignedMessagef->getClientFilename();
        $sSignedMessage = $sSignedMessagef->getStream()->getContents();
        // $myFile->moveTo('uploads/' . $uploadFileName);
    }

    $dataInBase64f = $uploadedFiles['dataInBase64'];
        if ($dataInBase64f->getError() === UPLOAD_ERR_OK) {
            $uploadFileName = $dataInBase64f->getClientFilename();
            $dataInBase64 = $dataInBase64f->getStream()->getContents();
            // $myFile->moveTo('uploads/' . $uploadFileName);
        }


    // $this->getFile($request);
    // $this->checkEmptyFile();

    $sd = new \CPSignedData;
    $sd->set_ContentEncoding(BASE64_TO_BINARY);
    $sd->set_Content($dataInBase64);
    // Бросает исключение
    $sd->VerifyCades($sSignedMessage, CADES_BES, true);

    $data = [
      'status' => 'ok'
    ];
      ];

    $signers = $sd->get_Signers();
    $data['signers'] = $this->getSignersInfo($signers);

  ];

    $signers = $sd->get_Signers();
    $data['signers'] = $this->getSignersInfo($signers);
 
     // Возможно получить все сертификаты, в том числе просто приложенные
     // $certificates = $sd->get_Certificates();
     // $data['certificates'] = $this->getCertsInfo($certificates);

    return $response->withJson($data);
  }

    return $response->withJson($data);
  }
