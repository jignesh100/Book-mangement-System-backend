from datetime import timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from sqlalchemy import false

app = Flask(__name__)


app.config['SECRET_KEY'] = 'YeMeriKeyHAi'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(20), default='customer') 
    def to_json(self):
        return {
            "id":self.id,
            "name":self.name,
            "email":self.email,
            "role": self.role
        }
    
class Books(db.Model):
    b_id = db.Column(db.Integer, primary_key=True)
    b_name = db.Column(db.String(100))
    b_auth = db.Column(db.String(100))
    b_isbn = db.Column(db.String(20), unique=True)
    b_pub_year = db.Column(db.Integer)
    b_check = db.Column(db.Boolean)

    def to_json(self):
        return {
            "b_id": self.b_id,
            "b_name": self.b_name,
            "b_auth": self.b_auth,
            "b_isbn": self.b_isbn,
            "b_pub_year": self.b_pub_year,
            "b_check": self.b_check
        }

with app.app_context():
    db.create_all()

app.config["JWT_SECRET_KEY"] = "super-secret" 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def login():
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        _pass = data.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.password == _pass: 
            access_token = create_access_token(identity=user.email, additional_claims={"role": user.role})
            refresh_token = create_refresh_token(identity=user.email, additional_claims={"role": user.role})

        else:  
            return {"message":"Invalide credaintials!"}
    
    return jsonify({"access_token":access_token,"refresh_token":refresh_token})
    

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role')

        if not name or not email or not password or not role:
            return jsonify({'message': 'Please pass all details!'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'Email already registered'}), 400

        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({'message': 'User created successfully!'}),201

    return jsonify({'message': 'Please send a POST request to create a user.'}), 200



@app.route('/signout', methods=['POST'])
@jwt_required()
def signout():
    return jsonify({"message": "Signed out successfully !"}), 200


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    user = User.query.filter_by(email=identity).first()
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    new_access_token = create_access_token(identity=identity, additional_claims={"role": user.role})
    return jsonify(access_token=new_access_token), 200


@app.route('/dashboard',methods=["POST"])
@jwt_required()
def dashboard():
    c_user=get_jwt_identity()
    user = User.query.filter_by(email=c_user).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    all_books = Books.query.all()
    books_json = [book.to_json() for book in all_books]
    return jsonify({
        'message': f'Welcome to the dashboard, {user.name} !',
        'user': user.to_json(),
        'books':books_json
    })

@app.route('/admin_dashboard',methods=["POST"])
@jwt_required()
def ad_dashboard():
    
    c_user=get_jwt_identity()
    jwt_data = get_jwt()
    user_role = jwt_data.get("role")
    user = User.query.filter_by(email=c_user).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    if user_role != 'admin':
        return jsonify({'message': 'Access denied: Admins only'}), 403
    
    all_books=Books.query.all()
    books_json = [book.to_json() for book in all_books]
    
    return jsonify({
        'message': f'Welcome to the ADMIN dashboard, {user.name} !',
        'user': user.to_json(),
        'books': books_json
    })



#admin Section

@app.route('/addbook', methods=['POST'])
@jwt_required()
def add_book():
    jwt_data = get_jwt()
    user_role = jwt_data.get("role")

    if user_role != 'admin':
        return jsonify({'message': 'Access denied: Admins only'}), 403
    
    data = request.get_json()
    b_name = data.get('b_name')
    b_auth = data.get('b_auth')
    b_isbn = data.get('b_isbn')
    b_pub_year = data.get('b_pub_year')

   
    existing_book = Books.query.filter_by(b_isbn=b_isbn).first()
    if existing_book:
        return jsonify({"message": "Book with this ISBN already exists!"}), 400

   
    new_book = Books(b_name=b_name, b_auth=b_auth, b_isbn=b_isbn, b_pub_year=b_pub_year, b_check=True)
    db.session.add(new_book)
    db.session.commit()

    return {"message":f"The Book {b_name} has Added !"}

@app.route('/delete_book/<int:b_id>', methods=['DELETE'])
@jwt_required()
def delete(b_id):
    jwt_data = get_jwt()
    user_role = jwt_data.get("role")

    if user_role != 'admin':
        return jsonify({'message': 'Access denied: Admins only'}), 403
    
    book = Books.query.filter_by(b_id=b_id).first()
    if not book:
        return jsonify({"message": "Book not found"}), 404

    db.session.delete(book)
    db.session.commit()
    return {"message": f"The Book {book.b_name} has been Deleted Successfully!"}


@app.route('/update_book/<int:b_id>',methods=["POST"])
@jwt_required()
def update(b_id):
    jwt_data=get_jwt()
    user_role= jwt_data.get("role")
    if user_role !='admin':
        return jsonify({'message': 'Access denied: Admins only'}), 403
    
    book =Books.query.filter_by(b_id=b_id).first()

    data= request.get_json()
    book.b_name=data.get('b_name')
    book.b_auth=data.get('b_auth')
    book.b_isbn=data.get('b_isbn')
    book.b_pub_year=data.get('b_pub_year')     
    book.b_check=data.get('b_check')           
    db.session.commit()

    return {"message":"The Book Updated Successfully!"}


if __name__=="__main__":
    app.run(debug=False,host="0.0.0.0",port=8080)