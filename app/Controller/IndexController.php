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
    // Hyperf will automatically generate a `/index/index` route for this method, allowing GET or POST requests
    public function index(RequestInterface $request)
    {
        // Retrieve the id parameter from the request
        $id = $request->input('сырники11', 1);
        // Transfer $id parameter to a string, and return $id to the client with Content-Type:plain/text
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

    public function sign(RequestInterface $request, ResponseInterface $response)
    {
        // 1) Проверки входа
        if (! $request->hasFile('document')) {
            return $this->xmlError($response, 'Файл не загружен', 400);
        }

        $file = $request->file('document');

        if (! $file->isValid()) {
            return $this->xmlError($response, 'Ошибка загрузки файла', 400);
        }

        // 2) Подготовка путей
        $saveDir = BASE_PATH . '/runtime/uploads';
        if (! is_dir($saveDir)) {
            @mkdir($saveDir, 0777, true);
        }

        // получить оригинальное имя безопасно
        $clientName = $file->getClientFilename() ?: 'uploaded.pdf';
        // формируем временное имя (чтобы не перезаписать)
        $tmpFilename = time() . '_' . bin2hex(random_bytes(6)) . '_' . $clientName;
        $tmpPath = $saveDir . '/' . $tmpFilename;

        // Перемещаем файл во временную папку (moveTo) — это корректно для Swoole uploaded file
        try {
            $file->moveTo($tmpPath);
        } catch (\Throwable $e) {
            return $this->xmlError($response, 'Не удалось сохранить временный файл: ' . $e->getMessage(), 500);
        }

        // 3) Настройки KalkanCrypt
        // Путь к контейнеру .p12 или сертификату
        $containerPath = BASE_PATH . '/utils/' . \Hyperf\Support\env('EDS_NAME'); // <-- укажи свой файл
        if (! file_exists($containerPath)) {
            @unlink($tmpPath);
            return $this->xmlError($response, 'Контейнер .p12 не найден на сервере', 500);
        }

        // Пароль из env
        $password = \Hyperf\Support\env('EDS_PASS', '');
        if ($password === '') {
            @unlink($tmpPath);
            return $this->xmlError($response, 'Не задан пароль к контейнеру (EDS_PASS)', 500);
        }

        // Подключаем константы KalkanCrypt, если они лежат в отдельном файле
        $flagsFile = BASE_PATH . '/utils/kalkanFlags&constants.php';
        if (file_exists($flagsFile)) {
            require_once $flagsFile;
        } else {
            // Если нет — продолжим, но константы должны быть где-то определены
        }

        // Инициализация
        try {
            KalkanCrypt_Init();
            // Опционально установить TSA URL
            KalkanCrypt_TSASetURL("http://tsp.pki.gov.kz");
        } catch (\Throwable $e) {
            @unlink($tmpPath);
            return $this->xmlError($response, 'Ошибка инициализации KalkanCrypt: ' . $e->getMessage(), 500);
        }

        // Загрузка контейнера (KCST_PKCS12 — константа из константного файла)
        $alias = "";
        $storage = $KCST_PKCS12;
        $err = KalkanCrypt_LoadKeyStore($storage, $password, $containerPath, $alias);
        if ($err > 0) {
            $errStr = function_exists('KalkanCrypt_GetLastErrorString') ? KalkanCrypt_GetLastErrorString() : "ErrCode={$err}";
            KalkanCrypt_Finalize();
            @unlink($tmpPath);
            return $this->xmlError($response, 'Ошибка загрузки контейнера: ' . $errStr, 500);
        }

        // 4) Подписание
        $outSign = "";
        // Входные данные — путь к файлу (строка) и соответствующие флаги
        $flags_sign = $KC_SIGN_CMS + $KC_IN_FILE + $KC_OUT_BASE64 + $KC_WITH_TIMESTAMP;

        try {
            $err = KalkanCrypt_SignData("", $flags_sign, $tmpPath, $outSign);
        } catch (\Throwable $e) {
            KalkanCrypt_Finalize();
            @unlink($tmpPath);
            return $this->xmlError($response, 'Исключение при подписании: ' . $e->getMessage(), 500);
        }

        if ($err > 0) {
            $errStr = function_exists('KalkanCrypt_GetLastErrorString') ? KalkanCrypt_GetLastErrorString() : "ErrCode={$err}";
            KalkanCrypt_Finalize();
            @unlink($tmpPath);
            return $this->xmlError($response, 'Ошибка при подписи: ' . $errStr, 500);
        }

        // outSign содержит подпись в base64 (если KC_OUT_BASE64 включён)
        // 5) Собираем XML-ответ
        $xml = new \SimpleXMLElement("<?xml version='1.0' encoding='UTF-8'?><data></data>");
        // оригинальный файл в base64 (если нужно)
        $orig = base64_encode(file_get_contents($tmpPath));
        $xml->addChild('document', $outSign);

        // Очистка
        KalkanCrypt_Finalize();
        // можно удалить временный файл, если не нужен
        @unlink($tmpPath);

        $xmlString = $xml->asXML();

        // Возвращаем XML как application/xml
        return $response
            ->withHeader('Content-Type', 'application/xml; charset=utf-8')
            ->withHeader('Content-Disposition', 'inline; filename="signed.xml"')
            ->withBody(new SwooleStream($xmlString));
    }

    /**
     * Вспомогательная функция: возвращает XML-ошибку
     */
    protected function xmlError(ResponseInterface $response, string $message, int $httpCode = 500)
    {
        $xml = new \SimpleXMLElement("<?xml version='1.0' encoding='UTF-8'?><error></error>");
        $xml->addChild('message', htmlspecialchars($message));
        $xml->addChild('code', (string)$httpCode);

        $xmlString = $xml->asXML();

        return $response
            ->withStatus($httpCode)
            ->withHeader('Content-Type', 'application/xml; charset=utf-8')
            ->withBody(new SwooleStream($xmlString));
    }

}