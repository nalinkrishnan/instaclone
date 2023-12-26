PRAGMA foreign_keys = ON;

CREATE TABLE users(
    username VARCHAR(20) NOT NULL PRIMARY KEY,
    fullname VARCHAR(40) NOT NULL,
    email VARCHAR(40) NOT NULL,
    filename VARCHAR(64) NOT NULL,
    password VARCHAR(256) NOT NULL,
    created DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts(
    postid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    filename VARCHAR(64) NOT NULL,
    owner VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE following(
    username1 VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    username2 VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    created DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username1, username2)
);

CREATE TABLE comments(
    commentid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    owner VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    postid INTEGER NOT NULL REFERENCES posts(postid) ON DELETE CASCADE,
    text VARCHAR(1024) NOT NULL,
    created DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE likes(
    likeid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    owner VARCHAR(20) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    postid INTEGER NOT NULL REFERENCES posts(postid) ON DELETE CASCADE,
    created DATETIME DEFAULT CURRENT_TIMESTAMP
);