## Исправленные блоки  блок кода:

### Часть 1: Приветствие пользователя (исправлен XSS)
Функция безопасного вывода:


    function safe_output($data) {
        return htmlspecialchars($data, ENT_QUOTES, UTF-8');
    }
    if (isset($_GET['username'])) {
        echo "Добро пожаловать, " . safe_output($_GET['username']) . "!";
    }

### Часть 2: Аутентификация (исправлена SQL-инъекция)

    if (isset($_POST['username']) && isset($_POST['password'])) {
        try {
            $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
            if ($conn->connect_error) throw new Exception("Connection failed");
            
            $stmt = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
            $stmt->bind_param("s", $_POST['username']);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                if (password_verify($_POST['password'], $user['password'])) {
                    // Успешная аутентификация
                    $_SESSION['user_id'] = $user['id'];
                    echo "Вход выполнен!";
                } else {
                    echo "Неверные учетные данные.";
                }
            } else {
                echo "Пользователь не найден.";
            }
            $stmt->close();
            $conn->close();
        } catch (Exception $e) {
            error_log("Database error: " . $e->getMessage());
            echo "Ошибка системы.";
        }
    }


### Часть 3: Небходимо удалить функционал с shell_exec()

### Часть 4: Необходимо выставить настройки безопасности для страницы:

    ini_set('display_errors', 0);
    error_reporting(0);
    session_start([
        'cookie_secure' => true,    // Только HTTPS
        'cookie_httponly' => true,  // Защита от XSS
        'cookie_samesite' => 'Lax'  // CSRF защита
    ]);

### Часть 5: Загрузка файлов:

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
        $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
        $max_size = 2 * 1024 * 1024; // 2MB
        $upload_dir = __DIR__ . '/uploads/';
        $extension = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
        $safe_name = bin2hex(random_bytes(8)) . '.' . $extension;

        if (
            $_FILES['file']['error'] === UPLOAD_ERR_OK &&
            in_array($_FILES['file']['type'], $allowed_types) &&
            $_FILES['file']['size'] <= $max_size &&
            in_array(strtolower($extension), ['jpg', 'png', 'pdf'])
        ) {
            if (move_uploaded_file($_FILES['file']['tmp_name'], $upload_dir . $safe_name)) {
                echo "Файл загружен как: " . safe_output($safe_name);
            } else {
                echo "Ошибка загрузки файла.";
            }
        } else {
            echo "Недопустимый файл. Разрешены JPG, PNG, PDF до 2MB.";
        }
    }

Проверяется тип файла (расширение) и ограничивается максимальный размер.


### Дополнительные меры безопасности
Необходимо изменить пользователя БД. Нельзя допускать исполнение пользовательских запросов под УЗ root.