<?php
declare(strict_types=1);

namespace App\Controller;

use Hyperf\HttpServer\Contract\RequestInterface;
use Hyperf\HttpServer\Annotation\AutoController;
use Hyperf\HttpServer\Contract\ResponseInterface;
use Hyperf\Context\ApplicationContext;
use Hyperf\HttpMessage\Stream\SwooleStream;

#[AutoController]
class IndexController
{
    public function index(RequestInterface $request)
    {
        $id = $request->input('сырники11', 1);
        return (string)$id;
    }


    public function uploadFile(RequestInterface $request)
    {
        if (! $request->hasFile('document')) {
            return $response->json(['error' => 'Файл не загружен']);
        }

        $file = $request->file('document');

        if (!$file->isValid()) {
            return $response->json(['error' => 'Ошибка загрузки']);
        }

        $fileContent = file_get_contents($file->getPathname());
        $fileAsBase64 = base64_encode($fileContent);

        $xml = new \SimpleXMLElement("<?xml version='1.0' standalone='yes'?><data></data>");
        $xml->addChild('document', $fileAsBase64);

        return $xml->asXML();
    }

    public function test(RequestInterface $request, ResponseInterface $response)
    {
        $savePath = BASE_PATH . '/runtime/tmp';
        if (!is_dir($savePath)) {
            mkdir($savePath, 0777, true);
        }

        require_once BASE_PATH . '/utils/' . \Hyperf\Support\env('EDS_CONSTANTS');

        if (! $request->hasFile('document')) {
            return $response->json(['error' => 'Файл не загружен']);
        }

        $file = $request->file('document');
        if (! $file->isValid()) {
            return $response->json(['error' => 'Ошибка загрузки']);
        }

        $certificate = BASE_PATH . '/utils/' . \Hyperf\Support\env('EDS_NAME');
        $password = \Hyperf\Support\env('EDS_PASS');

        KalkanCrypt_Init();
        KalkanCrypt_TSASetURL(\Hyperf\Support\env('EDS_URL'));
        $alias = "";
        $storage = $KCST_PKCS12;

        $err = KalkanCrypt_LoadKeyStore($storage, $password, $certificate, $alias);

        $outSign = "";
        $inData = $file->getPathname();
        $flags_sign = $KC_SIGN_CMS + $KC_IN_FILE + $KC_OUT_BASE64 + $KC_WITH_TIMESTAMP;

        $err = KalkanCrypt_SignData("", $flags_sign, $inData, $outSign);

        if ($err > 0) {
            $fileErr = $savePath . '/error_log.txt';
            file_put_contents($fileErr, KalkanCrypt_GetLastErrorString());
            KalkanCrypt_Finalize();
            return $response->json(['error' => 'Ошибка при подписании']);
        }

        $sigFileName = pathinfo($file->getClientFilename(), PATHINFO_FILENAME) . '_signed.pdf';
        $sigPath = $savePath . '/' . $sigFileName;

        $data = base64_decode($outSign);
        file_put_contents($sigPath, $data);

        KalkanCrypt_Finalize();

        return $response->download($sigPath, $sigFileName);
    }


    public function signFile(RequestInterface $request)
    {        
        $signData = $request->input('signData');

        $sigFileName = 'signature_' . '_' . time() . '.sig';
        $savePath = BASE_PATH . '/runtime/tmp';
        $certificate = BASE_PATH . '/utils/GOST512_fe3c3d8372520e7f91a6a69052eb8188225ac3f5.p12';
        $certificate = BASE_PATH . '/utils/kalkanFlags&constants.php';
        $password = env('EDS_PASS');

        KalkanCrypt_Init();
        KalkanCrypt_TSASetURL("http://tsp.pki.gov.kz");
        $alias = "";
        $storage = $KCST_PKCS12;
        $err = KalkanCrypt_LoadKeyStore($storage, $password,$certificate,$alias);

        $outSign = "";
        $inData = $pdf;
        $flags_sign = $KC_SIGN_CMS + $KC_IN_FILE + $KC_OUT_BASE64 + $KC_WITH_TIMESTAMP;
        $err = KalkanCrypt_SignData("", $flags_sign, $inData, $outSign);

        if ($err > 0){
            file_put_contents($fileErr,KalkanCrypt_GetLastErrorString());
            $err_sign = 1;
        }
        $data = base64_decode($outSign);

        file_put_contents($pdf,$data);

        KalkanCrypt_Finalize();
        

        if (!is_dir($savePath)) {
            mkdir($savePath, 0777, true);
        }

        $fullPath = $savePath . '/' . $sigFileName;

        file_put_contents($fullPath, $signData);

        return $response->withHeader('Content-Type', 'application/octet-stream')
        ->withHeader('Content-Disposition', "attachment; filename=\"{$sigFileName}\"")
        ->withBody(new \Hyperf\HttpMessage\Stream\SwooleStream(file_get_contents($fullPath)));
    }

}