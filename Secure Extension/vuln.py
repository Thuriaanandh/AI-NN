def get_user(db, user_id):
    query = "SELECT * FROM users WHERE id = %s" % user_id
    db.execute(query)
