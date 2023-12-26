"""REST API for posts."""
import hashlib
import flask
import insta485


def decode_password(password_dict, password):
    """Decode Password."""
    password_salt = password_dict.split('$')[1]
    encryption = 'sha512'
    hash_obj = hashlib.new(encryption)
    password_salted = password_salt + password
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([encryption, password_salt, password_hash])
    return password_db_string


def id_owner_created(connection, context, postid):
    """ID OWNER CREATED."""
    cur = connection.execute(
        "SELECT owner, created "
        "FROM posts "
        "WHERE postid = ?",
        (postid, )
    )
    owner = cur.fetchall()
    if len(owner) == 0:
        return flask.jsonify(**context)

    context['postid'] = postid
    context['owner'] = owner[0][0]
    context['created'] = owner[0][1]
    return None


def likes(connection, context, postid, username):
    """LIKES."""
    likes_dict = {}
    cur = connection.execute(
        "SELECT owner, postid "
        "FROM likes "
        "WHERE owner = ? "
        "AND postid = ?",
        (username, postid, )
    )
    logged = cur.fetchall()
    logged_bool = False
    if len(logged) == 1:
        logged_bool = True
    likes_dict['lognameLikesThis'] = logged_bool

    cur = connection.execute(
        "SELECT postid "
        "FROM likes "
        "WHERE postid = ?",
        (postid, )
    )
    total_likes = cur.fetchall()
    num_likes = len(total_likes)
    likes_dict['numLikes'] = num_likes

    if logged_bool is True:
        cur = connection.execute(
          "SELECT likeid "
          "FROM likes "
          "WHERE owner = ? "
          "AND postid = ?",
          (username, postid, )
        )
        like = cur.fetchall()
        likes_dict['url'] = f'/api/v1/likes/{like[0][0]}/'
    else:
        likes_dict['url'] = None

    context['likes'] = likes_dict


@insta485.app.route('/api/v1/')
def get_services():
    """Get Services."""
    context = {
        "comments": "/api/v1/comments/",
        "likes": "/api/v1/likes/",
        "posts": "/api/v1/posts/",
        "url": "/api/v1/"
    }
    return flask.jsonify(**context)


@insta485.app.route('/api/v1/posts/')
def get_recent_posts():
    """Get Recent Posts."""
    connection = insta485.model.get_db()
    context = {}

    username = ''

    if 'username' in flask.session:
        username = flask.session['username']
    else:
        if not flask.request.authorization or \
                'username' not in flask.request.authorization:
            return '', 403

        username = flask.request.authorization['username']
        password = flask.request.authorization['password']

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (username, )
        )
        password_dict = cur.fetchall()[0][0]

        if len(password_dict) == 0:
            return '', 403

        password_db_string = decode_password(password_dict, password)

        if password_db_string != password_dict:
            return '', 403

    context['url'] = flask.request.url[flask.request.url.find('/api/'):]
    # flask.request.query_string.decode()
    cur = connection.execute(
        "SELECT DISTINCT postid "
        "FROM posts "
        "INNER JOIN following "
        "ON (following.username1 = ? "
        "AND posts.owner = following.username2)"
        "OR posts.owner = ? "
        "ORDER BY postid DESC",
        (username, username, )
    )
    postids = cur.fetchall()
    postid_lte = postids[0][0]

    args = flask.request.args
    if 'postid_lte' in args:
        postid_lte = flask.request.args.get("postid_lte",
                                            default=postid_lte, type=int)

    size = flask.request.args.get("size", default=10, type=int)
    if size < 0:
        return '', 400

    page = flask.request.args.get("page", default=0, type=int)
    if page < 0:
        return '', 400

    cur = connection.execute(
        "SELECT DISTINCT postid "
        "FROM posts "
        "INNER JOIN following "
        "ON (following.username1 = ? "
        "AND posts.owner = following.username2)"
        "OR posts.owner = ? "
        "WHERE postid <= ? "
        "ORDER BY postid DESC "
        "LIMIT ? OFFSET ?",
        (username, username, postid_lte, size, size * page, )
    )
    postids = cur.fetchall()

    results = []
    context['results'] = results
    if len(postids) < size:
        context['next'] = ''
    else:
        context['next'] = (
            f'/api/v1/posts/?size={size}&page={page + 1}'
            f'&postid_lte={postid_lte}'
        )

    for postid in postids:
        res1 = {}
        res1['postid'] = postid[0]
        res1['url'] = f'/api/v1/posts/{postid[0]}/'
        results.append(res1)
        context['results'] = results

    return flask.jsonify(**context)


@insta485.app.route('/api/v1/posts/<int:postid>/')
def get_post(postid):
    """Get Post."""
    connection = insta485.model.get_db()

    cur = connection.execute(
        "SELECT MAX(postid) "
        "FROM posts",
        ()
    )
    highest_postid = cur.fetchall()[0][0]

    if postid < 1 or postid > highest_postid:
        return '', 404

    context = {}

    username = ''

    if 'username' in flask.session:
        username = flask.session['username']
    else:
        if not flask.request.authorization or \
                'username' not in flask.request.authorization:
            return '', 403

        username = flask.request.authorization['username']
        password = flask.request.authorization['password']

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (username, )
        )
        password_dict = cur.fetchall()[0][0]

        if len(password_dict) == 0:
            return '', 403

        password_db_string = decode_password(password_dict, password)

        if password_db_string != password_dict:
            return '', 403

    id_owner_created(connection, context, postid)

    likes(connection, context, postid, username)

    # owner_img_url
    cur = connection.execute(
        "SELECT filename "
        "FROM users "
        "WHERE username = ?",
        (context['owner'], )
    )
    owner_url = cur.fetchall()
    owner = context['owner']
    context['ownerImgUrl'] = f'/uploads/{owner_url[0][0]}'
    context['ownerShowUrl'] = f'/users/{owner}/'
    context['postShowUrl'] = f'/posts/{postid}/'
    context['url'] = f'/api/v1/posts/{postid}/'

    cur = connection.execute(
        "SELECT filename "
        "FROM posts "
        "WHERE postid = ?",
        (postid, )
    )
    context['imgUrl'] = f'/uploads/{cur.fetchall()[0][0]}'

    cur = connection.execute(
        "SELECT owner, text, commentid "
        "FROM comments "
        "WHERE postid = ?",
        (postid, )
    )

    comments = cur.fetchall()
    context_comments = []

    for comment in comments:
        comm_info = {}
        comm_info['owner'] = comment[0]
        comm_info['text'] = comment[1]
        comm_info['commentid'] = comment[2]
        comm_info['url'] = f'/api/v1/comments/{comment[2]}/'
        comm_info['ownerShowUrl'] = f'/users/{comment[0]}/'
        if comment[0] == username:
            comm_info['lognameOwnsThis'] = True
        else:
            comm_info['lognameOwnsThis'] = False
        context_comments.append(comm_info)

    context['comments'] = context_comments
    context['comments_url'] = f'/api/v1/comments/?postid={postid}'

    return flask.jsonify(**context)


@insta485.app.route('/api/v1/likes/', methods=['POST'])
def create_like():
    """Create Like."""
    connection = insta485.model.get_db()
    context = {}

    username = ''

    if 'username' in flask.session:
        username = flask.session['username']
    else:
        if not flask.request.authorization or \
                'username' not in flask.request.authorization:
            return '', 403

        username = flask.request.authorization['username']
        password = flask.request.authorization['password']

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (username, )
        )
        password_dict = cur.fetchall()[0][0]

        if len(password_dict) == 0:
            return '', 403

        password_db_string = decode_password(password_dict, password)

        if password_db_string != password_dict:
            return '', 403

    args = flask.request.args
    postid = args.get('postid')
    cur = connection.execute(
        "SELECT MAX(postid) "
        "FROM posts",
        ()
    )
    highest_postid = cur.fetchall()[0][0]

    if int(postid) < 1 or int(postid) > highest_postid:
        return '', 404

    cur = connection.execute(
        "SELECT likeid "
        "FROM likes "
        "WHERE owner = ? "
        "AND postid = ?",
        (username, postid, )
    )
    check_like = cur.fetchall()
    liked = False
    if len(check_like) > 0:
        liked = True
    if liked:
        context['likeid'] = check_like[0][0]
        context['url'] = f'/api/v1/likes/{check_like[0][0]}/'
        return flask.jsonify(**context), 200

    cur = connection.execute(
      "INSERT INTO likes "
      "(owner, postid) "
      "VALUES (?, ?)",
      (username, postid, )
    )
    connection.commit()
    cur = connection.execute(
      "SELECT likeid "
      "FROM likes "
      "WHERE owner = ? "
      "AND postid = ?",
      (username, postid, )
    )
    newlikeid = cur.fetchall()
    context['likeid'] = newlikeid[0][0]
    context['url'] = f'/api/v1/likes/{newlikeid[0][0]}/'
    return flask.jsonify(**context), 201


@insta485.app.route('/api/v1/likes/<likeid>/', methods=['DELETE'])
def delete_like(likeid):
    """Delete Like."""
    connection = insta485.model.get_db()

    username = ''

    if 'username' in flask.session:
        username = flask.session['username']
    else:
        if not flask.request.authorization or \
                'username' not in flask.request.authorization:
            return '', 403

        username = flask.request.authorization['username']
        password = flask.request.authorization['password']

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (username, )
        )
        password_dict = cur.fetchall()[0][0]

        if len(password_dict) == 0:
            return '', 403

        salt = password_dict.split('$')[1]
        algorithm = 'sha512'
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])

        if password_db_string != password_dict:
            return '', 403

    cur = connection.execute(
        "SELECT owner "
        "FROM likes "
        "WHERE likeid = ?",
        (likeid, )
    )
    num_rows = cur.fetchall()
    if len(num_rows) == 0:
        return '', 404
    if num_rows[0][0] != username:
        return '', 403
    cur = connection.execute(
        "DELETE FROM likes "
        "WHERE likeid = ?",
        (likeid, )
    )
    connection.commit()
    return '', 204


@insta485.app.route('/api/v1/comments/', methods=['POST'])
def add_comment():
    """Add Comment."""
    connection = insta485.model.get_db()
    context = {}
    username = ''

    if 'username' in flask.session:
        username = flask.session['username']
    else:
        if not flask.request.authorization or \
                'username' not in flask.request.authorization:
            return '', 403

        username = flask.request.authorization['username']
        password = flask.request.authorization['password']

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (username, )
        )
        password_dict = cur.fetchall()[0][0]

        if len(password_dict) == 0:
            return '', 403

        password_db_string = decode_password(password_dict, password)

        if password_db_string != password_dict:
            return '', 403

    args = flask.request.args
    postid = args['postid']
    cur = connection.execute(
        "SELECT MAX(postid) "
        "FROM posts",
        ()
    )
    highest_postid = cur.fetchall()[0][0]

    if int(postid) < 1 or int(postid) > highest_postid:
        return '', 404
    cur = connection.execute(
        "INSERT INTO comments "
        "(owner, postid, text)"
        "VALUES (?, ?, ?)",
        (username, postid, flask.request.get_json().get('text', ''), )
    )
    connection.commit()

    cur = connection.execute(
        "SELECT last_insert_rowid() "
        "FROM comments",
    )
    commentid = cur.fetchall()
    context['commentid'] = commentid[0][0]

    context['lognameOwnsThis'] = True
    context['owner'] = username
    context['ownerShowUrl'] = f'/users/{username}/'
    context['text'] = flask.request.get_json().get('text', '')
    context['url'] = f'/api/v1/comments/{commentid[0][0]}'

    return flask.jsonify(**context), 201


@insta485.app.route('/api/v1/comments/<commentid>/', methods=['DELETE'])
def delete_comment(commentid):
    """Delete Comment."""
    connection = insta485.model.get_db()
    username = ''

    if 'username' in flask.session:
        username = flask.session['username']
    else:
        if not flask.request.authorization or \
                'username' not in flask.request.authorization:
            return '', 403

        username = flask.request.authorization['username']
        password = flask.request.authorization['password']

        cur = connection.execute(
            "SELECT password "
            "FROM users "
            "WHERE username = ?",
            (username, )
        )
        password_dict = cur.fetchall()[0][0]

        if len(password_dict) == 0:
            return '', 403

        salt = password_dict.split('$')[1]
        algorithm = 'sha512'
        hash_obj = hashlib.new(algorithm)
        password_salted = salt + password
        hash_obj.update(password_salted.encode('utf-8'))
        password_hash = hash_obj.hexdigest()
        password_db_string = "$".join([algorithm, salt, password_hash])

        if password_db_string != password_dict:
            return '', 403
    cur = connection.execute(
        "SELECT commentid, owner "
        "FROM comments "
        "WHERE commentid = ?",
        (commentid, )
    )
    comment_id = cur.fetchall()
    if len(comment_id) == 0:
        return '', 404
    if comment_id[0][1] != username:
        return '', 403
    cur = connection.execute(
      "DELETE FROM comments "
      "WHERE commentid = ?",
      (commentid, )
    )
    connection.commit()
    return '', 204
