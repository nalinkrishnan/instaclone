"""
Insta485 index (main) view.

URLs include:
/
"""
import os
import pathlib
import uuid
import hashlib
import flask
from flask import session, redirect, request
import insta485


insta485.app.secret_key = insta485.app.config['SECRET_KEY']


def throw_error():
    """Display / route."""
    if 'username' not in session:
        flask.abort(403)


def throw_error_2(form):
    """Display / route."""
    if 'username' not in form or 'password' not in form:
        flask.abort(400)


def throw_error_3(files):
    """Display / route."""
    if 'file' not in files:
        flask.abort(400)


def throw_error_4(form):
    """Display / route."""
    if 'password' not in form or 'username' not in form or \
            'fullname' not in form or 'email' not in form:
        flask.abort(400)


def throw_error_5(form):
    """Display / route."""
    if 'fullname' not in form or 'email' not in form:
        flask.abort(400)


def confirm_password(password_dict, form):
    """Display / route."""
    password = password_dict[0][0]
    salt = password.split('$')[1]
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + form['password']
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    if password_db_string != password:
        flask.abort(403)


def create_password(form):
    """Display / route."""
    algorithm = 'sha512'
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password = form['password']
    password_salted = salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string


def update_password(response, form):
    """Display / route."""
    password = response[0][0]
    salt = password.split('$')[1]
    algorithm = 'sha512'
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + form['password']
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    if password_db_string != password:
        flask.abort(403)

    if form['new_password1'] != form['new_password2']:
        flask.abort(401)

    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + form['new_password1']
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string


def edit_account_helper(form, files1, files2, connection, url):
    """Display / route."""
    throw_error()

    throw_error_5(form)

    if 'file' not in files1:
        cur = connection.execute(
            "UPDATE users "
            "SET fullname = ?, "
            "email = ? "
            "WHERE username = ?",
            (form['fullname'], form['email'], session['username'], )
        )
        connection.commit()
        return redirect(url)

    # dont forget to delete old image from uploads
    fileobj = files2["file"]

    stem = uuid.uuid4().hex
    suffix = pathlib.Path(fileobj.filename).suffix.lower()
    uuid_basename = f"{stem}{suffix}"

    path = insta485.app.config['UPLOAD_FOLDER']/uuid_basename
    fileobj.save(path)

    cur = connection.execute(
        "SELECT filename "
        "FROM users "
        "WHERE username = ?",
        (session['username'], )
    )
    old_filename = cur.fetchall()[0][0]

    cur = connection.execute(
        "UPDATE users "
        "SET fullname = ?, "
        "email = ?, "
        "filename = ? "
        "WHERE username = ?",
        (form['fullname'], form['email'],
            uuid_basename, session['username'], )
    )
    connection.commit()

    os.remove(str(insta485.app.config['UPLOAD_FOLDER']) + f'/{old_filename}')
    return None


@insta485.app.route('/')
def show_index():
    """Display / route."""
    # Connect to database

    context = {}

    # logged in user
    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    return flask.render_template("index.html", **context)


@insta485.app.route('/users/<username>/')
def user_page(username):
    """Display /users/ route."""
    connection = insta485.model.get_db()

    context = {}

    # logged in user
    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username = ?",
        (username, )
    )
    users = cur.fetchall()
    if len(users) == 0:
        flask.abort(404)

    context['username'] = username

    # logname_follows_username
    cur = connection.execute(
        "SELECT username1, username2 "
        "FROM following "
        "WHERE username1 = ? "
        "AND username2 = ?",
        (context['logname'], username, )
    )
    logname_follows_username = cur.fetchall()
    if len(logname_follows_username) == 1:
        context['logname_follows_username'] = True
    else:
        context['logname_follows_username'] = False

    # fullname
    cur = connection.execute(
        "SELECT fullname "
        "FROM users "
        "WHERE username = ?",
        (username, )
    )
    fullname = cur.fetchall()
    context['fullname'] = fullname[0][0]

    # following
    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ?",
        (username, )
    )
    following_res = cur.fetchall()
    context['following'] = len(following_res)

    # followers
    cur = connection.execute(
        "SELECT username1 "
        "FROM following "
        "WHERE username2 = ?",
        (username, )
    )
    followers_res = cur.fetchall()
    context['followers'] = len(followers_res)

    # posts
    cur = connection.execute(
        "SELECT postid, filename "
        "FROM posts "
        "WHERE owner = ?",
        (username, )
    )

    posts = cur.fetchall()
    context['total_posts'] = len(posts)

    context_posts = []

    for post in posts:
        post_info = {}
        post_info['postid'] = post[0]
        post_info['img_url'] = f'/uploads/{post[1]}'
        context_posts.append(post_info)

    context['posts'] = context_posts

    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<username>/followers/')
def followers_page(username):
    """Display /followers/ route."""
    connection = insta485.model.get_db()

    context = {}

    # logged in user
    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    context['username'] = username

    cur = connection.execute(
        "SELECT username1 "
        "FROM following "
        "WHERE username2 = ?",
        (username, )
    )
    namefollowers = cur.fetchall()

    followers = []
    for namefollower in namefollowers:
        follower_info = {}
        follower_info['username'] = namefollower[0]

        cur = connection.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username = ?",
            (namefollower[0], )
        )
        user_url = cur.fetchall()
        follower_info['user_img_url'] = f'/uploads/{user_url[0][0]}'

        cur = connection.execute(
            "SELECT username1, username2 "
            "FROM following "
            "WHERE username1 = ? "
            "AND username2 = ?",
            (context['logname'], follower_info['username'])
        )
        follow_quest = cur.fetchall()
        if len(follow_quest) == 1:
            follower_info['logname_follows_username'] = True
        else:
            follower_info['logname_follows_username'] = False
        followers.append(follower_info)

    context['followers'] = followers

    return flask.render_template("followers.html", **context)


@insta485.app.route('/users/<username>/following/')
def following_page(username):
    """Display /following/ route."""
    connection = insta485.model.get_db()

    context = {}

    # logged in user
    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    context['username'] = username

    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ?",
        (username, )
    )
    namefollowing = cur.fetchall()
    following = []
    for namefollower in namefollowing:
        follower_info = {}
        # all users curretn user is following one user at a time
        follower_info['username'] = namefollower[0]

        cur = connection.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username = ?",
            (namefollower[0], )
        )
        user_url = cur.fetchall()
        follower_info['user_img_url'] = f'/uploads/{user_url[0][0]}'

        cur = connection.execute(
            "SELECT username1, username2 "
            "FROM following "
            "WHERE username1 = ? "
            "AND username2 = ?",
            (context['logname'], follower_info['username'])
        )
        follow_quest = cur.fetchall()
        if len(follow_quest) == 1:
            follower_info['logname_follows_username'] = True
        else:
            follower_info['logname_follows_username'] = False
        following.append(follower_info)

    context['following'] = following

    return flask.render_template("following.html", **context)


# @insta485.app.route('/posts/<postid>/')
# def post_page(postid):
#     """Display /posts/ route."""
#     connection = insta485.model.get_db()

#     context = {}

#     # logged in user
#     if 'username' in session:
#         context["logname"] = session["username"]
#     else:
#         return redirect(flask.url_for('login_page'))

#     context['postid'] = postid

#     cur = connection.execute(
#         "SELECT owner, created "
#         "FROM posts "
#         "WHERE postid = ?",
#         (postid, )
#     )
#     owner = cur.fetchall()
#     context['owner'] = owner[0][0]
#     context['timestamp'] = arrow.get(owner[0][1],
#                                      'YYYY-MM-DD HH:mm:ss').humanize()

#     cur = connection.execute(
#         "SELECT owner, postid "
#         "FROM likes "
#         "WHERE owner = ? "
#         "AND postid = ?",
#         (context['logname'], postid, )
#     )
#     logged = cur.fetchall()
#     logged_bool = False
#     if len(logged) == 1:
#         logged_bool = True
#     context['loggedLiked'] = logged_bool

#     # owner_img_url
#     cur = connection.execute(
#         "SELECT filename "
#         "FROM users "
#         "WHERE username = ?",
#         (context['owner'], )
#     )
#     owner_url = cur.fetchall()
#     context['owner_img_url'] = f'/uploads/{owner_url[0][0]}'

#     cur = connection.execute(
#         "SELECT filename "
#         "FROM posts "
#         "WHERE postid = ?",
#         (postid, )
#     )
#     img_url = cur.fetchall()
#     context['img_url'] = f'/uploads/{img_url[0][0]}'

#     cur = connection.execute(
#         "SELECT postid "
#         "FROM likes "
#         "WHERE postid = ?",
#         (postid, )
#     )
#     likes = cur.fetchall()
#     num_likes = len(likes)
#     context['likes'] = num_likes

#     cur = connection.execute(
#         "SELECT owner, text, commentid "
#         "FROM comments "
#         "WHERE postid = ?",
#         (postid, )
#     )

#     comments = cur.fetchall()
#     context_comments = []

#     for comment in comments:
#         comm_info = {}
#         comm_info['owner'] = comment[0]
#         comm_info['text'] = comment[1]
#         comm_info['commentid'] = comment[2]
#         context_comments.append(comm_info)

#     context['comments'] = context_comments

#     return flask.render_template("post.html", **context)


@insta485.app.route('/accounts/login/')
def login_page():
    """Display /accounts/ route."""
    context = {}
    # logged in user
    if 'username' in session:
        return redirect(flask.url_for('show_index'))

    return flask.render_template("login.html", **context)


@insta485.app.route('/explore/')
def explore_page():
    """Display /explore/ route."""
    connection = insta485.model.get_db()

    context = {}

    # logged in user
    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    cur = connection.execute(
        "SELECT username2 "
        "FROM following "
        "WHERE username1 = ?",
        (context['logname'], )
    )
    following = cur.fetchall()
    following_list = []
    for user in following:
        following_list.append(user[0])

    cur = connection.execute(
        "SELECT username, filename "
        "FROM users",
    )
    users = cur.fetchall()
    not_following = []
    for user in users:
        if user[0] not in following_list and user[0] != context['logname']:
            data = {}
            data['username'] = user[0]
            data['user_img_url'] = f'/uploads/{user[1]}'
            not_following.append(data)
    context['not_following'] = not_following

    return flask.render_template("explore.html", **context)


@insta485.app.route('/accounts/create/')
def create_accounts():
    """Display /accounts/ route."""
    context = {}

    if 'username' in session:
        return redirect(flask.url_for('edit_account'))

    return flask.render_template("create.html", **context)


@insta485.app.route('/accounts/delete/')
def delete_account():
    """Display /accounts/ route."""
    context = {}

    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    return flask.render_template("delete.html", **context)


@insta485.app.route('/accounts/edit/')
def edit_account():
    """Display /accounts/ route."""
    connection = insta485.model.get_db()
    context = {}

    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    # profile_pic, fullname, email
    cur = connection.execute(
        "SELECT filename, fullname, email "
        "FROM users "
        "WHERE username = ?",
        (context['logname'], )
    )
    fullname = cur.fetchall()
    context['profile_pic'] = f'/uploads/{fullname[0][0]}'
    context['fullname'] = fullname[0][1]
    context['email'] = fullname[0][2]

    return flask.render_template("edit.html", **context)


@insta485.app.route('/accounts/password/')
def change_password():
    """Display /password/ route."""
    context = {}

    if 'username' in session:
        context['logname'] = session["username"]
    else:
        return redirect(flask.url_for('login_page'))

    return flask.render_template("password.html", **context)


@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout_account():
    """Display /accounts/ route."""
    session.pop('username', None)
    return redirect(flask.url_for('login_page'))


@insta485.app.route('/likes/', methods=['POST'])
def likes_update():
    """Display /likes/ route."""
    connection = insta485.model.get_db()
    url = flask.request.args.get('target', flask.url_for('show_index'))

    if flask.request.form['operation'] == 'like':
        cur = connection.execute(
            "SELECT * "
            "FROM likes "
            "WHERE owner = ? "
            "AND postid = ?",
            (session['username'], flask.request.form['postid'], )
        )

        if len(cur.fetchall()) > 0:
            flask.abort(409)

        cur = connection.execute(
            "INSERT INTO likes "
            "(owner, postid) "
            "VALUES (?, ?)",
            (session['username'], flask.request.form['postid'], )
        )
        connection.commit()
    else:
        cur = connection.execute(
            "SELECT * "
            "FROM likes "
            "WHERE owner = ? "
            "AND postid = ?",
            (session['username'], flask.request.form['postid'], )
        )

        if len(cur.fetchall()) == 0:
            flask.abort(409)

        cur = connection.execute(
            "DELETE FROM likes "
            "WHERE owner = ? "
            "AND postid = ?",
            (session['username'], flask.request.form['postid'], )
        )
        connection.commit()

    return redirect(url)


@insta485.app.route('/comments/', methods=['POST'])
def comments_update():
    """Display /comments/ route."""
    connection = insta485.model.get_db()
    url = flask.request.args.get('target', flask.url_for('show_index'))

    if request.form['operation'] == 'create':
        if 'text' not in flask.request.form:
            flask.abort(400)

        cur = connection.execute(
            "INSERT INTO comments "
            "(owner, postid, text) "
            "VALUES(?, ?, ?)",
            (session['username'], flask.request.form['postid'],
                flask.request.form['text'], )
        )
        connection.commit()

    # delete
    else:
        # if deleting comment not owned by user
        cur = connection.execute(
            "SELECT owner "
            "FROM comments "
            "WHERE commentid = ?",
            (flask.request.form['commentid'])
        )
        check = cur.fetchall()
        if session['username'] != check[0][0]:
            flask.abort(403)

        cur = connection.execute(
            "DELETE FROM comments "
            "WHERE commentid = ?",
            (flask.request.form['commentid'])
        )
        connection.commit()

    return redirect(url)


@insta485.app.route('/posts/', methods=['POST'])
def posts_update():
    """Display /posts/ route."""
    connection = insta485.model.get_db()
    url = flask.request.args.get('target',
                                 flask.url_for('user_page',
                                               username=session['username']))

    if flask.request.form['operation'] == 'create':
        if 'file' not in request.files:
            flask.abort(400)

        fileobj = request.files["file"]

        stem = uuid.uuid4().hex
        suffix = pathlib.Path(fileobj.filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        path = insta485.app.config['UPLOAD_FOLDER']/uuid_basename
        fileobj.save(path)

        cur = connection.execute(
            "INSERT INTO posts "
            "(filename, owner) "
            "VALUES (?, ?)",
            (uuid_basename, session['username'], )
        )
        connection.commit()
    else:
        cur = connection.execute(
            "SELECT filename "
            "FROM posts "
            "WHERE postid = ? "
            "AND owner = ?",
            (flask.request.form['postid'], session['username'], )
        )
        post_data = cur.fetchall()

        if len(post_data) == 0:
            flask.abort(403)

        os.remove(str(insta485.app.config['UPLOAD_FOLDER']) +
                  f'/{post_data[0][0]}')

        cur = connection.execute(
            "DELETE FROM posts "
            "WHERE postid = ? "
            "AND owner = ?",
            (flask.request.form['postid'], session['username'], )
        )
        connection.commit()

    return redirect(url)


@insta485.app.route('/following/', methods=["POST"])
def follow_update():
    """Display /following/ route."""
    connection = insta485.model.get_db()
    url = flask.request.args.get('target', flask.url_for('show_index'))

    if flask.request.form['operation'] == "follow":
        cur = connection.execute(
            "SELECT username1, username2 "
            "FROM following "
            "WHERE username1 = ? "
            "AND username2 = ?",
            (session["username"], flask.request.form['username'], )
        )
        logname_follows_username = cur.fetchall()
        if len(logname_follows_username) == 1:
            flask.abort(409)

        cur = connection.execute(
            "INSERT INTO following (username1, username2) "
            "VALUES (?, ?)",
            (session["username"], flask.request.form['username'], )
        )
        connection.commit()
    else:
        cur = connection.execute(
            "SELECT username1, username2 "
            "FROM following "
            "WHERE username1 = ? "
            "AND username2 = ?",
            (session["username"], flask.request.form['username'], )
        )
        logname_follows_username = cur.fetchall()
        if len(logname_follows_username) == 0:
            flask.abort(409)

        cur = connection.execute(
            "DELETE FROM following "
            "WHERE username1 = ? "
            "AND username2 = ?",
            (session["username"], flask.request.form['username'], )
        )
        connection.commit()

    return redirect(url)


@insta485.app.route('/accounts/', methods=["POST"])
def accounts_update():
    """Display /accounts/ route."""
    connection = insta485.model.get_db()
    url = flask.request.args.get('target', flask.url_for('show_index'))

    if flask.request.form['operation'] == "login":
        throw_error_2(flask.request.form)

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (flask.request.form['username'], )
        )
        password_dict = cur.fetchall()

        if len(password_dict) == 0:
            flask.abort(403)

        confirm_password(password_dict, flask.request.form)

        session['username'] = flask.request.form['username']
    elif flask.request.form['operation'] == "create":
        # Unpack flask object
        throw_error_3(flask.request.files)

        throw_error_4(flask.request.form)

        fileobj = flask.request.files["file"]
        filename = fileobj.filename

        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)

        password_db_string = create_password(flask.request.form)

        cur = connection.execute(
            "INSERT INTO users (username, fullname, email, filename, password)"
            "VALUES (?, ?, ?, ?, ?) ",
            (flask.request.form['username'], flask.request.form['fullname'],
                flask.request.form['email'], uuid_basename,
                password_db_string, )
        )
        connection.commit()

        session['username'] = flask.request.form['username']
    elif flask.request.form['operation'] == "delete":  # AP
        throw_error()

        cur = connection.execute(
            "SELECT filename "
            "FROM posts "
            "WHERE owner = ?",
            (session['username'], )
        )
        post_files = cur.fetchall()

        for file in post_files:
            os.remove(str(insta485.app.config['UPLOAD_FOLDER']) +
                      f'/{file[0]}')

        cur = connection.execute(
            "SELECT filename "
            "FROM users "
            "WHERE username = ?",
            (session['username'], )
        )
        icon = cur.fetchall()[0][0]
        os.remove(str(insta485.app.config['UPLOAD_FOLDER']) + f'/{icon}')

        cur = connection.execute(
            "DELETE FROM users "
            "WHERE username = ?",
            (session["username"], )
        )
        connection.commit()
        session.pop('username', None)
    elif flask.request.form['operation'] == "edit_account":
        edit_account_helper(flask.request.form, request.files,
                            flask.request.files, connection, url)
    # update password
    else:
        throw_error()

        if 'password' not in flask.request.form or \
            'new_password1' not in flask.request.form or \
                'new_password2' not in flask.request.form:
            flask.abort(400)

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?;",
            (session['username'], )
        )

        password_db_string = update_password(cur.fetchall(),
                                             flask.request.form)

        cur = connection.execute(
            "UPDATE users "
            "SET password = ? "
            "WHERE username = ?",
            (password_db_string, session['username'], )
        )
        connection.commit()

    return redirect(url)


@insta485.app.route('/uploads/<filename>')
def display_file(filename):
    """Display /uploads/ route."""
    if 'username' not in session:
        flask.abort(403)

    if not os.path.exists(str(insta485.app.config['UPLOAD_FOLDER']) +
                          f'/{filename}'):
        flask.abort(404)

    return flask.send_from_directory(insta485.app.config['UPLOAD_FOLDER'],
                                     filename)
