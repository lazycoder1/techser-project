from flask import Flask, render_template, redirect, url_for, session, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, PasswordField, BooleanField, DateTimeField, SelectField
from wtforms.fields.html5 import DateField
from wtforms.validators import InputRequired, Email, Length, Optional
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
import pandas as pd
import datetime

ITEMS_PER_PAGE = 50

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost:3306/radius'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin , db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    employee_no = db.Column(db.String(10), unique= True)
    designation = db.Column(db.String(10))

class radcheck(db.Model):
    __tablename__ = 'radcheck'
    id = db.Column('id',db.Integer, primary_key=True)
    op = db.Column('op',db.String(2))
    username = db.Column(db.String(64), unique=True)
    value = db.Column(db.String(64))
    Department = db.Column('Department',db.String(64))
    E_mail = db.Column('E-mail', db.String(64))
    Phone = db.Column('Phone No', db.String(64))
    D_O_E = db.Column('Expiry Date', db.DateTime)
    Name = db.Column('Name',db.String(64))
    PRN = db.Column('PRN', db.String(16))
    Designation = db.Column('Designation', db.String(50))




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=80)])
    first_name = StringField('first_name', validators=[InputRequired(), Length(min=1, max=15)])
    last_name = StringField('last_name', validators=[InputRequired(), Length(min=1, max=15)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    employee_no = StringField('employee_no', validators=[InputRequired(), Length(min=1, max=15)])
    designation = StringField('designation', validators=[InputRequired(), Length(min=1, max=15)])

class SearchForm(FlaskForm):
    macid = StringField("Mac ID")
    value = StringField("Password")
    Name = StringField("Name")
    department = StringField("department")
    email = StringField('email')
    Phone = StringField("Phone No")
    D_O_E = DateField('Expiry date',validators = [Optional()],render_kw = {'placeholder':'1995-12-30'})
    PRN = StringField('Employee No/PRN', validators=[Optional(),Length(16,message='Enter a valid Employee No')])
    Designation = SelectField('Designation', choices=[('Staff', 'Staff'),
                                                      ('Student', 'Student')])


class FileForm(FlaskForm):
    csv = FileField(validators=[FileRequired()])



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods = ['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'

    return render_template('login.html',form = form)

@app.route('/signup',methods = ['GET','POST'])
@login_required
def signup():
    reg_form = RegisterForm()

    if reg_form.validate_on_submit():
        hashed_password = generate_password_hash(reg_form.password.data, method='sha256')
        new_user = User(username=reg_form.username.data,
                        email=reg_form.email.data,
                        password=hashed_password,
                        first_name=reg_form.first_name.data,
                        last_name= reg_form.last_name.data,
                        employee_no=reg_form.employee_no.data,
                        designation=reg_form.designation.data)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'

    return render_template('signup.html',form = reg_form)

@app.route('/dashboard',methods=['GET','POST'])
@app.route('/dashboard/<int:page>', methods=['GET', 'POST'])
@login_required
def dashboard(page = 1):
    form = SearchForm()
    posts = radcheck.query.paginate(page, ITEMS_PER_PAGE, False)
    return render_template('dashboard.html', name=current_user.username,posts = posts,form = form)

@app.route('/search',methods=['GET','POST'])
@app.route('/search/<int:page>', methods=['GET', 'POST'])
@login_required
def search(page = 1):
    form = SearchForm()
    if form.validate_on_submit():
        kwargs = {}
        if form.macid.data != '':
            kwargs['username'] = form.macid.data
        if form.value.data !='':
            kwargs['value'] = form.macid.data
        if form.Name.data != '':
            kwargs['Name'] = form.Name.data
        if form.department.data != '':
            kwargs['Department'] = form.department.data
        if form.Designation.data != '':
            kwargs['Designation'] = form.Designation.data
        if form.D_O_E.data is not None:
            kwargs['D_O_E'] = form.D_O_E.data
        if form.PRN.data != '':
            kwargs['PRN'] = form.PRN.data
        if form.email.data != '':
            kwargs['E_mail'] = form.email.data
        if form.Phone.data != '':
            kwargs['Phone'] = form.Phone.data
        print(kwargs)
        session['search_query'] = kwargs
        session.modified = True
        posts = radcheck.query.filter_by(**session['search_query']).paginate(page, ITEMS_PER_PAGE, False)

        return render_template('search.html', name=current_user.username, posts=posts, form=form)
    print(form.errors)
    if 'search_query' in session:
        posts = radcheck.query.filter_by(**session['search_query']).paginate(page, ITEMS_PER_PAGE, False)
    else:
        posts = radcheck.query.paginate(page, ITEMS_PER_PAGE, False)
    return render_template('search.html', name=current_user.username,posts = posts,form = form)

@app.route('/add',methods=['GET','POST'])
@login_required
def add(mode='add'):
    form = SearchForm()
    if mode == 'add':
        if form.validate_on_submit():
            result = radcheck.query.filter_by(PRN=form.PRN.data).all()
            if len(result)>=2:
                return '<h1>This user already has 2 devices registered<h1>'

            new_radcheck = radcheck(
                op = ':=',
                username =form.macid.data,
                value = form.macid.data,
                Name = form.Name.data,
                PRN = form.PRN.data,
                Department = form.department.data,
                Designation = form.Designation.data,
                D_O_E = form.D_O_E.data,
                E_mail = form.email.data,
                Phone = form.Phone.data
            )
            db.session.add(new_radcheck)
            db.session.commit()
            return '<h1>New Entry Added<h1>'
    else:
        radcheck_edit = radcheck.query.filter_by(id = mode).first()

        return '<h1>New Entry Added<h1>'
    return render_template('add.html',name=current_user.username ,form=form)


@app.route('/edit',methods=['GET','POST'])
@login_required
def edit():
    form = SearchForm()
    print(request.method)
    if request.method == 'POST':
        radcheck_edit = radcheck.query.filter_by(id=request.form['id']).first()

        kwargs = {}
        print(form.macid.data)
        if form.macid.data != '':
            radcheck_edit.username = form.macid.data
            radcheck_edit.value = form.macid.data
        if form.Name.data != '':
            radcheck.Name = form.Name.data
        if form.PRN.data != '':
            radcheck_edit.PRN = form.PRN.data
        if form.department.data != '':
            radcheck_edit.Department = form.department.data
        if form.Designation.data != '':
            radcheck_edit.Designation = form.Designation.data
        if form.D_O_E.data is not None:
            radcheck_edit.D_O_E = form.D_O_E.data
        if form.email.data != '':
            radcheck_edit.E_mail = form.email.data
        if form.Phone.data != '':
            radcheck_edit.Phone = form.Phone.data
        db.session.add(radcheck_edit)
        db.session.commit()
        return '<h1>Edited</h1>'
    radcheck_edit = radcheck.query.filter_by(id=request.args.get('edit')).first()
    session['id'] = request.args.get('edit')
    return render_template('edit.html',name=current_user.username ,form=form,rad_id = radcheck_edit)

@app.route('/delete',methods=['GET','POST'])
@login_required
def delete():
    id = request.args.get('delete')
    radcheck_delete = radcheck.query.filter_by(id=id).first()
    db.session.delete(radcheck_delete)
    db.session.commit()
    return redirect(url_for('search'))

@app.route('/delete_all',methods=['GET','POST'])
@login_required
def delete_all():

    if request.args.get('mode') == 'delete_all':
        if 'search_query' in session:
            posts = radcheck.query.filter_by(**session['search_query'])
            for i in posts.items:
                db.session.delete(i)
                db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return "<h1>No search query entered</h1>"
    else:
        if 'search_query' in session:
            posts = radcheck.query.filter_by(**session['search_query']).paginate(int(request.args.get('mode')), ITEMS_PER_PAGE, False)
            for i in posts.items:
                db.session.delete(i)
                db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            return "<h1>No search query entered</h1>"

@app.route('/toggle',methods=['GET','POST'])
@login_required
def toggle():
    id = request.args.get('toggle')
    radcheck_toggle = radcheck.query.filter_by(id=id).first()
    if radcheck_toggle.op == ':=':
        radcheck_toggle.op = '!'
    else:
        radcheck_toggle.op = ':='
    db.session.commit()
    return redirect(url_for('search'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = FileForm()
    if form.validate_on_submit():
        f = form.csv.data
        data = pd.read_csv(f)
        # in development
        for index,row in data.iterrows():
            try:
                result = radcheck.query.filter_by(PRN=row[2]).all()
                if len(result) >= 2:
                    continue
                new_radcheck = radcheck(
                    op = ':=',
                    username=row[0],
                    value=row[0],
                    Name=row[1],
                    PRN = row[2],
                    Phone=row[3],
                    E_mail=row[4],
                    Department=row[5],
                    Designation = row[6],
                    D_O_E = datetime.datetime.strptime(row[7], "%Y-%m-%d")
                )
                db.session.add(new_radcheck)
                db.session.commit()
            except:
                continue
        return '<H1>Done<H1>'





    return render_template('upload.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
