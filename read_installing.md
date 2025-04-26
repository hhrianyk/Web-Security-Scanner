# Руководство по установке системы на сервер

## Содержание
1. [Подготовка к установке](#подготовка-к-установке)
2. [Установка операционной системы](#установка-операционной-системы)
3. [Настройка сети](#настройка-сети)
4. [Установка необходимого программного обеспечения](#установка-необходимого-программного-обеспечения)
5. [Настройка брандмауэра](#настройка-брандмауэра)
6. [Настройка удаленного доступа](#настройка-удаленного-доступа)
7. [Установка и настройка базы данных](#установка-и-настройка-базы-данных)
8. [Установка веб-сервера](#установка-веб-сервера)
9. [Развертывание приложения](#развертывание-приложения)
10. [Настройка мониторинга](#настройка-мониторинга)
11. [Резервное копирование](#резервное-копирование)
12. [Установка инструментов безопасности](#установка-инструментов-безопасности)
13. [Настройка окружения для AI-компонентов](#настройка-окружения-для-ai-компонентов)

## Подготовка к установке

### Требования к оборудованию
- Процессор: минимум 2 ядра, рекомендуется 4+ ядра
- Оперативная память: минимум 4 ГБ, рекомендуется 8+ ГБ
- Дисковое пространство: минимум 20 ГБ, рекомендуется 50+ ГБ (SSD)
- Сетевой интерфейс: Gigabit Ethernet

### Подготовка носителя для установки
1. Скачайте образ операционной системы с официального сайта
2. Создайте загрузочную USB-флешку с помощью программ:
   - Rufus (для Windows)
   - Etcher (кроссплатформенный)
   - dd (для Linux/MacOS): `sudo dd if=путь_к_образу.iso of=/dev/sdX bs=4M status=progress`

## Установка операционной системы

### Первоначальная настройка BIOS/UEFI
1. Включите сервер и войдите в BIOS/UEFI (обычно клавиши F2, Delete, F10 или F12)
2. Настройте порядок загрузки, установив USB-носитель первым в списке
3. Активируйте аппаратную виртуализацию (если требуется)
4. Сохраните настройки и перезагрузите сервер

### Процесс установки
1. Загрузитесь с установочного носителя
2. Выберите язык установки (русский)
3. Настройте разметку дисков:
   - Рекомендуемая схема разделов:
     - /boot: 1 ГБ
     - swap: равен или в 1.5 раза больше объема ОЗУ
     - /: оставшееся пространство (или выделить отдельные разделы под /var, /home)
4. Установите базовую систему
5. Настройте часовой пояс и локаль
6. Создайте учетную запись администратора и задайте надежный пароль
7. Дождитесь завершения установки и перезагрузите сервер

## Настройка сети

### Базовая настройка сети
1. Определите сетевые интерфейсы: `ip a`
2. Настройте статический IP-адрес, отредактировав конфигурационный файл:
   
   **Для систем на базе Debian/Ubuntu:**
   ```
   sudo nano /etc/network/interfaces
   ```
   
   Пример настройки:
   ```
   auto eth0
   iface eth0 inet static
     address 192.168.1.100
     netmask 255.255.255.0
     gateway 192.168.1.1
     dns-nameservers 8.8.8.8 8.8.4.4
   ```
   
   **Для систем на базе RHEL/CentOS:**
   ```
   sudo nano /etc/sysconfig/network-scripts/ifcfg-eth0
   ```
   
   Пример настройки:
   ```
   DEVICE=eth0
   BOOTPROTO=static
   IPADDR=192.168.1.100
   NETMASK=255.255.255.0
   GATEWAY=192.168.1.1
   DNS1=8.8.8.8
   DNS2=8.8.4.4
   ONBOOT=yes
   ```

3. Настройте hostname:
   ```
   sudo hostnamectl set-hostname server-name
   ```
   
4. Обновите файл `/etc/hosts`:
   ```
   127.0.0.1   localhost
   127.0.1.1   server-name
   192.168.1.100 server-name
   ```

5. Перезапустите сетевую службу:
   ```
   sudo systemctl restart networking   # Debian/Ubuntu
   # или
   sudo systemctl restart network      # RHEL/CentOS
   ```

## Установка необходимого программного обеспечения

### Обновление системы
```
# Debian/Ubuntu
sudo apt update
sudo apt upgrade -y

# RHEL/CentOS
sudo yum update -y
# или
sudo dnf update -y
```

### Установка базовых утилит
```
# Debian/Ubuntu
sudo apt install -y vim wget curl htop tmux git unzip net-tools

# RHEL/CentOS
sudo yum install -y vim wget curl htop tmux git unzip net-tools
# или
sudo dnf install -y vim wget curl htop tmux git unzip net-tools
```

## Настройка брандмауэра

### Настройка iptables
1. Установка:
   ```
   # Debian/Ubuntu
   sudo apt install -y iptables-persistent
   
   # RHEL/CentOS
   sudo yum install -y iptables-services
   ```

2. Базовые правила:
   ```
   # Очистить все правила
   sudo iptables -F
   
   # Установить политики по умолчанию
   sudo iptables -P INPUT DROP
   sudo iptables -P FORWARD DROP
   sudo iptables -P OUTPUT ACCEPT
   
   # Разрешить локальные соединения
   sudo iptables -A INPUT -i lo -j ACCEPT
   
   # Разрешить установленные соединения
   sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
   
   # Разрешить SSH (порт 22)
   sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
   
   # Разрешить HTTP/HTTPS
   sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
   
   # Сохранить правила
   sudo netfilter-persistent save  # Debian/Ubuntu
   # или
   sudo service iptables save      # RHEL/CentOS
   ```

### Настройка firewalld (для RHEL/CentOS)
```
sudo systemctl enable firewalld
sudo systemctl start firewalld

# Открыть нужные порты
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=8080/tcp  # Пример для дополнительного порта

# Применить изменения
sudo firewall-cmd --reload
```

## Настройка удаленного доступа

### Настройка SSH
1. Отредактируйте файл конфигурации:
   ```
   sudo nano /etc/ssh/sshd_config
   ```

2. Рекомендуемые настройки безопасности:
   ```
   # Запретить вход под root
   PermitRootLogin no
   
   # Использовать только протокол SSH v2
   Protocol 2
   
   # Отключить аутентификацию по паролю (только ключи)
   PasswordAuthentication no
   
   # Изменить стандартный порт (опционально)
   Port 2222
   
   # Ограничить доступ определенным пользователям
   AllowUsers username1 username2
   ```

3. Перезапустите SSH-сервер:
   ```
   sudo systemctl restart sshd
   ```

### Настройка аутентификации по ключам
1. На клиентской машине создайте SSH-ключ:
   ```
   ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
   ```

2. Скопируйте публичный ключ на сервер:
   ```
   ssh-copy-id -i ~/.ssh/id_rsa.pub username@server_ip
   ```
   или вручную добавьте содержимое публичного ключа в файл `~/.ssh/authorized_keys` на сервере

## Установка и настройка базы данных

### Установка PostgreSQL
```
# Debian/Ubuntu
sudo apt install -y postgresql postgresql-contrib

# RHEL/CentOS
sudo yum install -y postgresql-server postgresql-contrib
sudo postgresql-setup initdb
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### Базовая настройка
1. Переключитесь на пользователя postgres:
   ```
   sudo -i -u postgres
   ```

2. Создайте пользователя и базу данных:
   ```
   createuser --interactive
   createdb database_name
   ```

3. Настройте аутентификацию, отредактировав файл `pg_hba.conf`:
   ```
   sudo nano /etc/postgresql/<version>/main/pg_hba.conf  # Debian/Ubuntu
   # или
   sudo nano /var/lib/pgsql/data/pg_hba.conf            # RHEL/CentOS
   ```

4. Перезапустите службу:
   ```
   sudo systemctl restart postgresql
   ```

## Установка веб-сервера

### Установка Nginx
```
# Debian/Ubuntu
sudo apt install -y nginx

# RHEL/CentOS
sudo yum install -y epel-release
sudo yum install -y nginx
```

### Базовая настройка
1. Создайте конфигурацию для вашего сайта:
   ```
   sudo nano /etc/nginx/sites-available/your-site.conf  # Debian/Ubuntu
   # или
   sudo nano /etc/nginx/conf.d/your-site.conf          # RHEL/CentOS
   ```

2. Пример конфигурации:
   ```
   server {
       listen 80;
       server_name your-domain.com www.your-domain.com;
       
       root /var/www/your-site;
       index index.html index.htm index.php;
       
       location / {
           try_files $uri $uri/ =404;
       }
       
       # Пример конфигурации для PHP
       location ~ \.php$ {
           include snippets/fastcgi-php.conf;
           fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
       }
       
       # Запретить доступ к .htaccess файлам
       location ~ /\.ht {
           deny all;
       }
   }
   ```

3. Активируйте конфигурацию (для Debian/Ubuntu):
   ```
   sudo ln -s /etc/nginx/sites-available/your-site.conf /etc/nginx/sites-enabled/
   ```

4. Проверьте конфигурацию и перезапустите Nginx:
   ```
   sudo nginx -t
   sudo systemctl restart nginx
   ```

## Развертывание приложения

### Настройка окружения для приложения
1. Установите необходимые зависимости (пример для Node.js):
   ```
   # Debian/Ubuntu
   curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
   sudo apt install -y nodejs
   
   # RHEL/CentOS
   curl -sL https://rpm.nodesource.com/setup_14.x | sudo bash -
   sudo yum install -y nodejs
   ```

2. Создайте директорию для приложения:
   ```
   sudo mkdir -p /var/www/your-app
   sudo chown -R $USER:$USER /var/www/your-app
   ```

3. Клонируйте репозиторий с приложением:
   ```
   git clone https://github.com/your-user/your-app.git /var/www/your-app
   ```

4. Установите зависимости и соберите приложение:
   ```
   cd /var/www/your-app
   npm install
   npm run build
   ```

5. Настройте процесс-менеджер (например, PM2):
   ```
   sudo npm install -g pm2
   pm2 start app.js
   pm2 startup
   pm2 save
   ```

## Настройка мониторинга

### Установка и настройка мониторинга
```
# Установите Prometheus и Node Exporter
# Debian/Ubuntu
sudo apt install -y prometheus prometheus-node-exporter

# RHEL/CentOS
sudo yum install -y prometheus prometheus-node-exporter

# Настройте автозапуск
sudo systemctl enable prometheus
sudo systemctl enable prometheus-node-exporter
sudo systemctl start prometheus
sudo systemctl start prometheus-node-exporter
```

## Резервное копирование

### Настройка регулярного резервного копирования
1. Создайте скрипт для резервного копирования:
   ```
   nano /usr/local/bin/backup.sh
   ```

2. Пример скрипта:
   ```bash
   #!/bin/bash
   
   BACKUP_DIR="/backup"
   DATE=$(date +%Y-%m-%d_%H-%M-%S)
   
   # Резервное копирование базы данных
   pg_dump -U username database_name > $BACKUP_DIR/db_$DATE.sql
   
   # Резервное копирование файлов приложения
   tar -czf $BACKUP_DIR/app_$DATE.tar.gz /var/www/your-app
   
   # Очистка старых резервных копий (старше 7 дней)
   find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
   find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
   ```

3. Сделайте скрипт исполняемым:
   ```
   chmod +x /usr/local/bin/backup.sh
   ```

4. Добавьте задачу в crontab:
   ```
   crontab -e
   ```
   
   Добавьте строку для ежедневного резервного копирования в 02:00:
   ```
   0 2 * * * /usr/local/bin/backup.sh
   ```

## Установка инструментов безопасности

Система интегрирует множество инструментов безопасности, каждый из которых может потребовать дополнительную установку и настройку.

### Автоматическая установка всех зависимостей

Наиболее простой способ установки всех необходимых инструментов - использовать скрипт автоматической установки:

```bash
# Linux/Mac
./install_security_tools.sh

# Windows
install_security_tools.bat
```

### Установка основных инструментов сканирования

#### Nmap

Nmap - один из ключевых инструментов, используемых для сканирования портов и определения сервисов.

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y nmap
```

**RHEL/CentOS:**
```bash
sudo yum install -y nmap
```

**Windows:**
```
# Используйте скрипт автоматической установки
Install-Nmap.ps1

# Или добавьте nmap в PATH
add_nmap_to_path.bat
```

#### OWASP ZAP

**Linux/Mac:**
```bash
# Загрузите последнюю версию с сайта OWASP ZAP
wget https://github.com/zaproxy/zaproxy/releases/download/v2.11.1/ZAP_2.11.1_Linux.tar.gz
tar -xvf ZAP_2.11.1_Linux.tar.gz
```

**Windows:**
```
# Загрузите и установите EXE файл с официального сайта
# https://www.zaproxy.org/download/
```

#### W3af

W3af требуется для функционирования модуля AI-имитации ручного тестирования.

```bash
# Клонирование репозитория
git clone https://github.com/andresriancho/w3af.git
cd w3af

# Установка зависимостей
./w3af_console
# При первом запуске будет предложено установить зависимости
```

### Установка Python-зависимостей

Система основана на Python и требует установки множества пакетов:

```bash
# Установка основных зависимостей
pip install -r requirements.txt

# Установка зависимостей для инструментов безопасности
pip install -r requirements_security_tools.txt
```

Если вы обновили систему до последней версии:
```bash
pip install -r new_requirements_security_tools.txt
```

### Установка интеграций с коммерческими инструментами

#### Nessus

1. Загрузите Nessus с официального сайта: https://www.tenable.com/downloads/nessus
2. Установите согласно инструкциям для вашей ОС
3. Получите лицензию (доступна бесплатная домашняя лицензия)
4. Настройте API-ключ в файле `.env`

#### Metasploit Framework

**Linux:**
```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
```

**Windows:**
Загрузите установщик с официального сайта Rapid7.

### Проверка установленных инструментов

После установки всех инструментов рекомендуется проверить их работоспособность:

```bash
# Проверка основных инструментов
python verify_security_tools.py
```

## Настройка окружения для AI-компонентов

Система использует несколько AI-моделей для анализа уязвимостей и генерации отчетов. Для полноценной работы необходимо настроить API-ключи.

### Создание файла окружения

Скопируйте шаблон файла окружения:

```bash
cp .env.template .env
```

Отредактируйте файл `.env`, добавив свои API-ключи:

```
# OpenAI API Key (для GPT-4)
OPENAI_API_KEY=sk-ваш-ключ

# IBM Watson API (для Watson for Cybersecurity)
IBM_WATSON_API_KEY=ваш-ключ-watson
IBM_WATSON_URL=https://api.watson-url.com/

# Anthropic API Key (для Claude)
ANTHROPIC_API_KEY=sk-ant-ваш-ключ

# Google API Key (для Gemini)
GOOGLE_API_KEY=ваш-ключ-google

# Другие настройки
MONGODB_URI=mongodb://localhost:27017/security_scanner
```

### Проверка API-ключей

```bash
python verify_api_keys.py
```

При успешной настройке вы увидите сообщение о статусе каждого API-ключа.

### Дополнительные настройки для AI-моделей

В файле `unified_config.json` можно настроить параметры AI-моделей:

```json
{
  "ai_settings": {
    "default_provider": "openai",
    "openai_model": "gpt-4",
    "anthropic_model": "claude-3-opus-20240229",
    "google_model": "gemini-pro",
    "temperature": 0.2,
    "max_tokens": 4000
  }
}
```

## Запуск системы

После установки всех компонентов вы можете запустить систему:

```bash
# Linux/Mac
./run_unified_security.sh

# Windows
run_unified_security.bat
```

Веб-интерфейс будет доступен по адресу:
```
http://localhost:5000
```

## Устранение типичных проблем установки

### Ошибки импорта Python-модулей

При ошибках импорта проверьте наличие всех необходимых пакетов:

```bash
pip install -r requirements.txt
pip install -r requirements_security_tools.txt
```

### Проблемы с Nmap

Если Nmap не определяется системой:

```bash
# Windows
python fix_nmap_detection.py

# Linux
sudo ln -s /usr/bin/nmap /usr/local/bin/nmap
```

### Проблемы с доступом к MongoDB

Убедитесь, что MongoDB запущена и доступна:

```bash
# Проверка MongoDB
python check_mongodb.py

# Запуск MongoDB, если не запущена
python run_mongodb.py
```

### Проблемы с API-ключами

При ошибках авторизации API-ключей:
1. Проверьте, что ключи правильно скопированы в файл `.env`
2. Убедитесь, что ключи активны и не истекли
3. Проверьте достаточность средств/квот для использования API

### Восстановление после сбоев

В случае сбоев в работе системы можно использовать утилиту восстановления:

```bash
python fix_issues.py
```

После устранения проблем запустите систему с исправленными настройками:

```bash
start_fixed_system.bat
``` 