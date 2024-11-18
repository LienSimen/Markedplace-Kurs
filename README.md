https://markedplace-kurs.onrender.com/

## Prerequisites

- Node.js (version 14 or higher)
- MySQL (or MariaDB)
- Nodemon (optional, for development)

---

## Setup

Login to your db and query:

``` bash
CREATE DATABASE markedplace;
```

In Terminal:

```bash
git clone https://github.com/LienSimen/Markedplace-Kurs
cd markedplace-kurs
```

Create .env file in root folder, google cli/github can be left blank
``` bash
DB_HOST=localhost
DB_USER=user
DB_PASSWORD=password
DB_NAME=markedplace
DB_PORT=3306
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
```

``` bash
npm install
nodemon server.js
```




