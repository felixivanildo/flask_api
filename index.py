import jwt
from flask import Flask, make_response, jsonify, request
import psycopg2 as pg
from queries import select_all, login_query, is_admin, select_ressources_id, select_all_ressources, createnorm_user, promote_user_query, delete_query, delete_ressource_query, create_ressource_query, \
    update_ressource_query, alocate_ressource_query, login_query2
from psycopg2.extras import RealDictCursor
from base64 import b64encode
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt as JW
from pathlib import Path
from functools import  wraps
from datetime import timedelta, datetime
import socket

# hostname=socket.gethostname()
# IPAddr=socket.gethostbyname(hostname) 
# print(IPAddr)


connection = pg.connect(user='postgres', password='postgres', host='postgres' , port='5432',
                            database='mesha')

app = Flask (__name__, template_folder='pages')




def token_required(f):
    @wraps(f)
    def decorated (*args, **kwargs):
        token = None


        if 'acess-token' in request.headers:
            token = request.headers['acess-token']



        if not token:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(111,data)

            connection = pg.connect(user='postgres', password='postgres', host='127.0.0.1', port='5438',
                                    database='mesha')
            curs = connection.cursor()
            curs.execute(is_admin + "'" + data['name'] + "'")
            datax = curs.fetchall()
            print(datax)
            current_user = datax[0][3]

            

        except:
            return jsonify({'Message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'Status': 404, 'Error': 'Resource not found'}), 404)



@app.route("/users", methods=['GET'])
def get_users():

    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(select_all)
    data = curs.fetchall()
       
    return make_response(data)


@app.route("/users/<id>", methods=['GET'])
@token_required
def get_by_id(current_user, id):
    if not current_user:
       return jsonify({"message": "user is not an admin"})
    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(login_query + "'" + id + "'")
    data = curs.fetchall()
    

    if (data):
        return make_response(data)


    else:
        return ("Usuario não existe")


@app.route("/users", methods=['POST'])
def create_users():

    

    data = request.get_json()
    print(data)

    hashed_password = generate_password_hash(data['pwd'], method='sha1')
    print(hashed_password)

    curs = connection.cursor()
    curs.execute(createnorm_user, (data['email'], hashed_password, data['role']))
    connection.commit()
    

    return jsonify({ 'message': 'New user created'})

@app.route("/users", methods=['PUT'])
@token_required
def promote_user(current_user):
    if not current_user:
        return jsonify({"Message": "Not allowed"})
    data_req = request.get_json()
    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(login_query + "'" + data_req['email'] + "'")
    data = curs.fetchall()
    hashed_password = generate_password_hash(data_req['password'], method='sha1')


    if not data:
        return jsonify({'message': 'Nenhum usuario encontrado'})

    curs.execute(promote_user_query, (data_req['email'], hashed_password, data_req['role'], data_req['id']) )
    connection.commit()
    
    return jsonify({'message': 'Changed'})


@app.route ('/users', methods=["DELETE"])
@token_required
def delete_user(current_user):
    if not current_user:
        return jsonify({"Message": "Not allowed"})

    data_req = request.get_json()
    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(delete_query + str(data_req['id']))
    connection.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/login')
def login():
    
    curs = connection.cursor()

    auth = request.authorization

    if not auth or not auth.username or  not auth.password:
       return make_response('Não está logado', 401, {'WWW-authenticar': 'Basic realm="Login necessario"'})

    curs.execute(login_query2 + "'" + auth.username + "'")
    data = curs.fetchall()
    print(auth)
    user = data [0][1]
    password = data [0][2]
    print(auth.password)


    if not user:

        return make_response('Não está logado', 401, {'WWW-authenticar': 'Basic realm="Login necessario"'})

    if check_password_hash(password, auth.password):

        token = JW.encode({'name': user, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})

    

    return make_response('Não está logado', 401, {'WWW-authenticar': 'Basic realm="Login necessario"'})


@app.route('/ressources', methods=['GET'])

def get_ressources():
    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(select_all_ressources)
    data = curs.fetchall()
    
    return make_response(data)

@app.route('/ressources/search', methods=['GET'])
def get_ressources_id():
    data_req = request.get_json()
    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(select_ressources_id + str(data_req['id']))
    data = curs.fetchall()
    
    return make_response(data)

@app.route('/ressources', methods=['DELETE'])
@token_required
def delete_ressource(current_user):
    if not current_user:
        return jsonify({"message": "user is not an admin"})
    data_req = request.get_json()
    
    curs = connection.cursor(cursor_factory=pg.extras.RealDictCursor)
    curs.execute(delete_ressource_query + str(data_req['id']))
    connection.commit()
    return jsonify({'message': 'Deleted'})

@app.route('/ressources', methods=['POST'])
@token_required
def create_ressource(current_user):
    if not current_user:
        return jsonify({"message": "user is not an admin"})
    

    streak = request.get_json()
    curs = connection.cursor()
    curs.execute(create_ressource_query, (streak['produto'], streak['descricao'], streak['quantidade']))
    connection.commit()
    

    return jsonify({'message': 'New product created'})

@app.route('/ressources', methods=['PUT'])
@token_required
def update_ressources(current_user):
    if not current_user:
        return jsonify({"message": "user is not an admin"})

    

    streak = request.get_json()
    curs = connection.cursor()
    curs.execute(update_ressource_query, (streak['produto'], streak['descricao'], streak['quantidade'], streak['id']))
    connection.commit()
    

    return jsonify({'message': 'Product updated'})


@app.route('/ressources/<id>', methods=['PUT'])
def alocate_ressources(id):
   
    
    curs = connection.cursor()
    curs.execute(alocate_ressource_query, (datetime.today(), id))
    datex = datetime.today() + timedelta(days=30)
    solved = datex.strftime('%Y-%m-%d')
    curs.execute('UPDATE ressources SET columnto_be_retorned = %s where id = %s', (solved, id))
    connection.commit()
    
    return jsonify({'Message': 'Alocated'})

app.config ['SECRET_KEY'] = 'Felix'

if __name__ == '__main__':
    app.run(host='0.0.0.0')