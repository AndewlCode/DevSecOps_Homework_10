# DevSecOps_Homework_10

## Уязвимый блок кода:

    <?php
    // Уязвимый код веб-приложения
    if (isset($_GET['username']))
    {
        echo "Добро пожаловать, " . $_GET['username'] . "!";
    }
    if (isset($_POST['username']) && isset($_POST['password']))
    {
        $conn = new mysqli("localhost", "root", "", "testdb");
        $query = "SELECT * FROM users WHERE username = '" . $_POST['username'] . "' AND
    password = '" . $_POST['password'] . "'";
        $result = $conn->query($query);
        if ($result->num_rows > 0)
        {
            echo "Вход выполнен!";
        }
        else
        {
            echo "Неверные учетные данные.";
        }
    }
    if (isset($_GET['cmd']))
    {
        echo shell_exec($_GET['cmd']);
    }
    setcookie("session_id", "12345", time() + 3600);
    if ($_FILES['file']['error'] === UPLOAD_ERR_OK)
    {
        move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);
        echo "Файл загружен!";
    }
    ?>

## Ошибки и потенциальные опасности:
### Блок кода 1:

    if (isset($_GET['username']))
    {
        echo "Добро пожаловать, " . $_GET['username'] . "!";
    }

Проверяет, есть ли параметр 'username' в GET-запросе и выводит его без какой-либо обработки. Это XSS, потому что пользовательский ввод встраивается в HTML страницу, возвращаемую сервером. Злоумышленник может ввести JavaScript-код через параметр username, который выполнится в браузере.


### Блок кода 2:

    if (isset($_POST['username']) && isset($_POST['password']))
    {
        $conn = new mysqli("localhost", "root", "", "testdb");
        $query = "SELECT * FROM users WHERE username = '" . $_POST['username'] . "' AND
    password = '" . $_POST['password'] . "'";
        $result = $conn->query($query);
        if ($result->num_rows > 0)
        {
            echo "Вход выполнен!";
        }
        else
        {
            echo "Неверные учетные данные.";
        }
    }

Отвечает за аутентификацию. Параметры username и password из POST-запроса подставляются напрямую в SQL-запрос. Это пример SQL-инъекции. Например, если ввести ' OR '1'='1 в поле пароля, запрос может вернуть все записи, что позволит обойти аутентификацию.

Для подключения к БД используется учётная запись root. Если злоумышленник успешно проэксплуатирует SQL-инъекцию, то его запрос будет выполнен с максимальными правами, так же он может получить полный доступ к БД.

A03:2021-Injection SQL Injection (SQLi), A02:2021-Cryptographic Failures

### Блок кода 3:

    if (isset($_GET['cmd']))
    {
        echo shell_exec($_GET['cmd']);
    }

Проверяет параметр 'cmd' в GET-запросе и выполняет команду через shell_exec. Это возможность для злоумышленника выполнить произвольные команды на сервере (уязвимость Command Injection). Например, передав cmd=ls, можно получить список файлов.

A03:2021-Injection Command Injection

### Блок кода 4:

`
setcookie("session_id", "12345", time() + 3600);
`

Установка куки: session_id задается статическим значением без каких-либо признаков безопасности. Отсутствие флагов HttpOnly и Secure может позволить украсть куки через XSS или передачу по незащищенному соединению.

A01:2021-Broken Access Control


### Блок кода 5:


    if ($_FILES['file']['error'] === UPLOAD_ERR_OK)
    {
        move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);
        echo "Файл загружен!";
    }


Осуществляет загрузку файлов, перемещает загруженный файл в директорию /uploads без проверки типа файла. Это несёт риски загрузки вредоносных файлов, PHP-скриптов, которые могут быть выполнены на сервере.

A05:2021-Security Misconfiguration