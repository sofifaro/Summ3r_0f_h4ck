Уязвимости в приложении VibePass
---

***Тип: ContentProvider с доступом к логам***

***Уязвимый код:***
в AndroidManifest.xml
```XML
<provider
    android:name="ru.chudakov.vibepass.LogsExportProvider"
    android:exported="true"
    android:authorities="ru.chudakov.vibepass"/>
```
LogsExportProvider.java
```java
public ParcelFileDescriptor openFile(Uri uri, String str) throws FileNotFoundException {
    if (uri.getPath().startsWith("/logs/ly8pdwVLhai0mCTN")) {
        return ParcelFileDescriptor.open(new File(new File(getContext().getFilesDir(), "logs"), uri.getLastPathSegment()), 268435456);
    }
    return null;
}
```

**Риски:**
1. Любое приложение на устройстве может обратиться к content://ru.chudakov.vibepass/logs/ly8pdwVLhai0mCTN/<file_name> и прочитать любой файл из папки logs. Таким образом можно получить все логи приложения за всё время
2. Логирование мастер-пароля и PIN в открытом виде, а благодаря этой уязвимости мы сможем прочитать лог и полные учетные данные.
FullUnlockActivity.java
```java
this.passwordInput.addTextChangedListener(new TextWatcher() {
    @Override
    public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        FullUnlockActivity.this.unlockButton.setEnabled(charSequence.length() > 0);
        FullUnlockActivity.logger.d(FullUnlockActivity.TAG, "onTextChanged: " + charSequence.toString());
        ...........
    }
});
```
QuickUnlockActivity.java
```java
this.pinInput.addTextChangedListener(new TextWatcher() {
    @Override
    public void onTextChanged(CharSequence charSequence, int i, int i2, int i3) {
        QuickUnlockActivity.this.unlockButton.setEnabled(...);
        QuickUnlockActivity.logger.d(QuickUnlockActivity.TAG, "onTextChanged: " + QuickUnlockActivity.this.pinInput.getText().toString());
        ...........
    }
});
```

**Рекомендации по устранению:**
1. Установить android:exported="false"
2. Удалить логирование charSequence.toString() и любых других конфиденциальных данных.
3. Отключить запись в файл (isFileLoggingEnabled = false) или установить минимальный уровень логирования только для ошибок.
---

***Тип: Статичный ключ шифрования бд***

***Уязвимый код:***
VaultManager.java
```java
private byte[] getVaultKey() {
    try {
        byte[] bArrArray = ByteBuffer.allocate(8)
            .putLong(this.mContext.getPackageManager()
                .getPackageInfo(this.mContext.getPackageName(), 0).firstInstallTime)
            .array();
        ByteBuffer byteBufferAllocate = ByteBuffer.allocate(16);
        byteBufferAllocate.put(bArrArray);
        byteBufferAllocate.put(new byte[]{23, 31, 3, 1, 85, 55, 26, 77});
        return byteBufferAllocate.array();
    } catch (Exception e) {
        throw new RuntimeException("Failed to get vault key", e);
    }
}
```

**Риски:**
1. Ключ формируется из firstInstallTime (время первой установки приложения) и статического суффикса (firstInstallTime можно получить из PackageManager, а ключ подобрать), таким образом, злоумышленник может расшифровывать файл VibePass.db.locked и получить все пароли.

**Рекомендации по устранению:**
1. Хранить ключ только в памяти во время работы приложения, не записывать на диск и генерировать ключ с использованием случайной соли.

---

***Тип: PIN Brute-force***

***Уязвимый код:***
QuickUnlockActivity.java
```java
private void tryUnlock() {
    if (this.pinInput.getText().toString().trim().equals(this.sharedPrefsMgr.getVaultUnlockCode())) {
           ....
    } else {
        this.pinLayout.setError("Wrong PIN");
    }
}
```

**Риски:**
1. Злоумышленник может программно перебрать все комбинаций PIN. Проверка происходит локально, скорость перебора ограничена только производительностью.

**Рекомендации по устранению:**
1. Ввести счётчик неудачных попыток. После 3–5 ошибок увеличить задержку.
2. Добавить блокировку на 5–10 минут после N неудачных попыток.

---
