# Importted necessary dependencies for the application to work
from flask import Flask, redirect, render_template, request, url_for, session, flash, abort, send_file, send_from_directory
from flask_admin import Admin, BaseView, expose
from flask_admin_dashboard import AdminDashboard
import mimetypes
from datetime import datetime
import matplotlib.pyplot as plt
from flask_sqlalchemy import SQLAlchemy
from wtforms import widgets
from wtforms import SelectField
from flask_admin.contrib.sqla import ModelView
from flask_security import UserMixin
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from flask_bcrypt import Bcrypt, generate_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, current_user, login_required, login_user, LoginManager, logout_user, login_manager, AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.sql import func
from wtforms import BooleanField, IntegerField, PasswordField, StringField, SubmitField, TextAreaField, FileField, DateField,SelectMultipleField
from wtforms.validators import (DataRequired, InputRequired, Length)
from flask_wtf.file import FileField
from werkzeug.utils import secure_filename 
from datetime import datetime
from datetime import timedelta
from datetime import date
import os, sqlite3
import datetime
from flask_sqlalchemy import Pagination
from wtforms.validators import DataRequired
import json
from collections import Counter
from io import BytesIO
from wtforms import validators
import pytz

# Setting up the base directory of the project
basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
bcrypt = Bcrypt(app)


# Database configurations and other settings to make the database work
conn = sqlite3.connect ('database.db')
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=3)
db = SQLAlchemy(app)

UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'files')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Created the login manager and set its configuration (for login purpose)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.anonymous_user=AnonymousUserMixin
login_manager.login_message_category = "info"
login_manager.login_view = "memberpage"
login_manager.login_message = "Access denied! You\'ll have to Log in first!"
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Defined the database User model using SQLAlchemy
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    staffID = db.Column(db.String(50, collation='NOCASE'), nullable=True, unique=True)
    studentID = db.Column(db.String(20, collation='NOCASE'), nullable=False, unique=True)
    firstname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80, collation='NOCASE'), nullable=False, unique=True)
    phonenumber = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    password = db.Column(db.String(256), nullable=False)
    acc_verify = db.Column(db.Boolean, default=False, nullable=False, server_default='1')
    is_admin = db.Column(db.Boolean, default=False)
    clubs_registered = db.Column(db.String(100), nullable=True)

    def __init__(self, studentID, firstname, email, phonenumber, password, acc_verify, is_admin,clubs_registered,staffID):
        self.studentID = studentID
        self.staffID= staffID
        self.firstname = firstname
        self.email = email
        self.phonenumber = phonenumber
        self.password = generate_password_hash(password)
        self.acc_verify = bool(acc_verify)
        self.is_admin = bool(is_admin)
        self.clubs_registered = clubs_registered

    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)

    def __repr__(self):
        return f'''
        StudentID:{self.studentID} 
        '''


@app.before_first_request
def create_admin_user():
    db.create_all()
    new_admin = User(staffID='admin_flask',studentID='admin_flask', firstname='Developer Ragunath', email='flask_admin@gmail.com', phonenumber='0123247958', password='admin123', acc_verify=1, is_admin=1, clubs_registered='VOLTEN,UNICS,PRO-C')
    db.session.add(new_admin)
    db.session.commit()


class PaperworkSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_title = db.Column(db.String(200, collation='NOCASE'), nullable=False)
    club_name = db.Column(db.String(100), nullable=False)
    officer_name = db.Column(db.String(100), nullable=False)
    proposal_type = db.Column(db.String(100), nullable=False)
    event_date_paperwork = db.Column(db.String(100), nullable=False, default=date.today)
    remarks = db.Column(db.String(100), nullable=True)
    event_budget = db.Column(db.String(100), nullable=False)
    filename= db.Column(db.String(100), nullable=False)
    upload_proposal = db.Column(db.LargeBinary)

    def __init__(self, event_title, club_name, officer_name, proposal_type, remarks, event_budget,event_date_paperwork, filename,upload_proposal):
        self.event_title = event_title
        self.club_name = club_name
        self.officer_name = officer_name
        self.proposal_type = proposal_type
        self.remarks = remarks
        self.event_budget = event_budget
        self.filename = filename
        self.upload_proposal = upload_proposal
        self.event_date_paperwork = event_date_paperwork if event_date_paperwork else date.today()

    def __repr__(self):
        return f'''
        StudentID: {self.event_title} | {self.club_name}
        '''

class ReportSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    club_name = db.Column(db.String(100), nullable=False)
    event_title = db.Column(db.String(200, collation='NOCASE'), nullable=False)
    officer_name = db.Column(db.String(100), nullable=False)
    event_date_paperwork = db.Column(db.String(100), nullable=False, default=date.today)
    remarks = db.Column(db.String(100), nullable=True)
    filename= db.Column(db.String(100), nullable=False)
    upload_proposal = db.Column(db.LargeBinary)

    def __init__(self, event_title, club_name, officer_name, event_date_paperwork, remarks, filename, upload_proposal):
        self.event_title = event_title
        self.club_name = club_name
        self.officer_name = officer_name
        self.event_date_paperwork = event_date_paperwork if event_date_paperwork else date.today()
        self.remarks = remarks
        self.filename = filename
        self.upload_proposal = upload_proposal


    def __repr__(self):
        return f'''
        {self.event_title} | {self.club_name}
        '''
    

class ContactStudent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_to = db.Column(db.String(80, collation='NOCASE'), nullable=False)
    email_by = db.Column(db.String(80, collation='NOCASE'), nullable=False)
    sender_name = db.Column(db.String(80, collation='NOCASE'), nullable=False)
    body =  db.Column(db.String(10000), nullable=False)
    time_posted = db.Column(db.String(100), nullable=False)

    def __init__(self, email_to, email_by, body,sender_name,time_posted):
        self.email_to = email_to
        self.email_by = email_by
        self.body = body
        self.sender_name = sender_name
        self.time_posted = time_posted

    def __repr__(self):
        return f'''
        {self.sender_name}
        '''

    
@app.route("/write_to_students",methods=('GET','POST'))
def write():
    form = RegisterForm()
    malaysia_timezone = pytz.timezone('Asia/Kuala_Lumpur')
    current_timestamp = datetime.datetime.now(malaysia_timezone)
    current_user_email = current_user.email
    form.email_to.choices = [('','Please choose email')] + [(user.email, user.email) for user in User.query.all() if user.email != current_user_email ]
    form.email_to.validators = [validators.NoneOf([''], message='Please choose email')]
  
    
    if request.method == 'POST':
        email_to = form.email_to.data
        email_by = request.form.get('email_by')
        sender_name = request.form.get('sender_name')
        body = request.form.get('body')
        time_posted=request.form.get('time_posted')
        
        feedback = ContactStudent(
            email_to=email_to,
            email_by=email_by,
            sender_name=sender_name,
            time_posted=time_posted,
            body=body)
        
        db.session.add(feedback)
        db.session.commit()
        flash("Message sent successful")
        return redirect(url_for('write'))

    return render_template('write.html',form=form,current_timestamp=current_timestamp)




# Defined the registration form using FlaskForm
class RegisterForm(FlaskForm):
    studentID = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "studentID/StaffID"})
    firstname = StringField(validators=[InputRequired(), Length(min=3, max=20)], render_kw={"placeholder": "Your Name"})
    email = StringField(validators=[InputRequired(), DataRequired()], render_kw={"placeholder": "Email address"})
    phonenumber = StringField(validators=[InputRequired()], render_kw={"placeholder": "Your phone number"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    acc_verify = db.Column(db.Boolean, default=False, nullable=False, server_default='0')
    submit = SubmitField("Register")
    submit23 = SubmitField("Save")
    submit_paperwork= SubmitField("Upload Form")
    submit_reset = SubmitField("Change password")
    event_title = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Event title"})
    event_name = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Event Name"})
    club_name = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Club name"})
    officer_name = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Officer Name"})
    proposal_type = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "State your Proposal Type"})
    remarks = StringField(validators=[Length(min=1, max=100)], render_kw={"placeholder": "Your Remarks"})
    event_budget = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Yes/No"})
    upload_report = FileField("Upload Event Report")
    event_date_report = DateField('Submission Date', validators=[DataRequired()],render_kw={"placeholder": "Event Date"}, format='%Y-%m-%d')
    event_date_paperwork = DateField('Submission Date', validators=[DataRequired()],render_kw={"placeholder": "Event Date"}, format='%Y-%m-%d')
    time_posted = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Date and Time"})
    club_choices = [("", "Please choose"), ("VOLTEN", "VOLTEN"), ("UNICS", "UNICS"), ("PRO-C", "PRO-C")]
    clubs = SelectField('Club Registered', choices=club_choices, validators=[InputRequired()], default='', option_widget=widgets.CheckboxInput())

    officer_choices = [("", "Please choose"), ("Dr.Husni", "Dr.Husni"), ("Dr.Shamini", "Dr.Shamini"), ("Dr.Lim", "Dr.Lim")]
    officers = SelectField('Officers', choices=officer_choices,  validators=[InputRequired()], default='', option_widget=widgets.CheckboxInput())

    proposal_choices = [("", "Please choose"), ("Inside Campus", "Inside Campus"), ("Outside Campus", "Outside Campus"), ("Online", "Online")]
    proposals = SelectField('Proposal', choices=proposal_choices, validators=[InputRequired()], default='', option_widget=widgets.CheckboxInput())
    email_to = SelectField('Email', validators=[InputRequired()], choices=[])
    email_by = StringField(validators=[InputRequired(), DataRequired()], render_kw={"placeholder": "Your Email address", "readonly": True})
    sender_name = StringField(validators=[InputRequired(), DataRequired()], render_kw={"placeholder": "Name of Sender", "readonly": True})
    body = TextAreaField('body', validators=[InputRequired()], render_kw={'placeholder': 'Enter your text here'})

    new_password = PasswordField('New Password')
    
    def set_email_choices(self, choices):
        self.email_to.choices = choices

class LoginForm(FlaskForm):
    studentID = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder"  :"studentID"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={" placeholder" :"Password"})
    submit = SubmitField("Login")

# ADMIN Configurations 
app.config['FLASK_ADMIN_SWATCH'] = 'Flatly'
admin = Admin(app, name='', template_mode='bootstrap3')

class ModelView(ModelView):
    can_export = True
    column_export_exclude_list = "password"
    column_exclude_list = ['password','upload_proposal','created_at']
    can_create = False
    can_view_details = True
    
    def is_accessible(self):
        if current_user.is_anonymous == True:
            return abort(404)
        if current_user.is_admin:
            return True
        if not current_user.is_admin:
            return abort(404)
        
    def inaccessible_callback(self, name, **kwargs):
        return abort(404)
    
    def edit_form(self, obj=None):
        form = super().edit_form(obj=obj)
        if 'password' in form:
            del form['password']
        if 'upload_report' in form:
            del form['upload_proposal']
        return form
    
# Custom ModelView subclasses
class UserModelView(ModelView):
    def __init__(self, session):
        super(UserModelView, self).__init__(User, session)

class PaperworkSubmissionModelView(ModelView):
    def __init__(self, session):
        super(PaperworkSubmissionModelView, self).__init__(PaperworkSubmission, session)

class ReportSubmissionModelView(ModelView):
    def __init__(self, session):
        super(ReportSubmissionModelView, self).__init__(ReportSubmission, session)

class ContactStudentModelView(ModelView):
    def __init__(self, session):
        super(ContactStudentModelView, self).__init__(ContactStudent, session)

# Add the custom ModelView instances to Flask-Admin
admin.add_view(UserModelView(db.session))
admin.add_view(PaperworkSubmissionModelView(db.session))
admin.add_view(ReportSubmissionModelView(db.session))
admin.add_view(ContactStudentModelView(db.session))

#Defining the route to access the pages
@app.route("/")
def homelayout():
    return render_template('home.html')

#After creating account, the user cant access the dashboard unless he is verified by the admin
@app.route("/member_loginpage/", methods=['GET','POST'])
def memberpage():
    form = LoginForm()
    studentID = form.studentID.data
    password = form.password.data

    if form.validate_on_submit(): 
        user = User.query.filter_by(studentID=studentID).first()

        if not user:
            flash("Invalid Login! User does not exist")
            return redirect(url_for('memberpage'))

        if user.acc_verify == 0:
            flash("Your application is on review",'danger')
            logout_user()
            session.pop('logged_in', None)
            return redirect(url_for('memberpage'))
        
        if user and user.verify_password(password):
            login_user(user, remember=True)
            session['logged_in'] = True

            if user.is_admin:
                return redirect(url_for('lecturer_space',page=1))
            else:
                return redirect(url_for('dashboard',page=1))

        else:
            flash("Please check your login details correctly and try again",'danger')
            return redirect(url_for('memberpage'))

    return render_template('member_loginpage.html', form=form)

@app.route("/logindashboard/<int:page>")
@login_required
def dashboard(page=1):
    malaysia_timezone = pytz.timezone('Asia/Kuala_Lumpur')
    current_timestamp = datetime.datetime.now(malaysia_timezone)
    per_page = 1  # Number of emails per page
    view_paperwork = PaperworkSubmission.query.all()
    view_feedback = ContactStudent.query.filter_by(email_to=current_user.email).paginate(page=page, per_page=per_page)
    form = RegisterForm()
    return render_template('logindashboard.html', form=form,view_paperwork=view_paperwork,view_feedback=view_feedback,current_timestamp=current_timestamp)


@app.route("/database_records")
@login_required
def databasespace():
    if current_user.is_admin:
        return redirect('/admin/')
    else:
        return abort(404)


@app.route("/submit_paperwork/", methods=['GET', 'POST'])
@login_required
def submitpaperwork():
    form = RegisterForm()
    allowed_formats = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']

    if request.method == 'POST':
        file = request.files['file']
        selected_clubs = form.clubs.data
        event_title = request.form.get('event_title')
        event_date_paperwork = request.form.get('event_date_paperwork')
        selected_officers = form.officers.data
        selected_proposal = form.proposals.data
        remarks = request.form.get('remarks')
        event_budget = request.form.get('event_budget')
      
        new_paperworksubmission = PaperworkSubmission(
            filename=file.filename,
            upload_proposal=file.read(),
            event_title=event_title,
            club_name=selected_clubs,
            officer_name=selected_officers,
            proposal_type=selected_proposal,
            remarks=remarks,
            event_budget=event_budget,
            event_date_paperwork=event_date_paperwork)

        if file.mimetype in allowed_formats:
            pass
        else:
            flash("Invalid File format! Only PDF and DOCX files are allowed!")
            return redirect(url_for('submiteventreport'))

        db.session.add(new_paperworksubmission)
        db.session.commit()
        flash("Paperwork Proposal submission for is successful")
        return redirect(url_for('submitpaperwork'))

    return render_template('/submitpaperwork.html', form=form)


@app.route("/download/<paperworksubmission_id>")
@login_required
def download(paperworksubmission_id):
    upload = PaperworkSubmission.query.filter_by(id=paperworksubmission_id).first()
    file_data = BytesIO(upload.upload_proposal)

    if not upload:
        flash("No file detected")
        return redirect(url_for("paperwork_records"))
    
    file_extension = os.path.splitext(upload.upload_proposal)[1]
    mimetype = mimetypes.types_map.get(file_extension, 'application/octet-stream')

    return send_file(file_data, mimetype=mimetype, download_name=upload.filename, as_attachment=True)



@app.route("/view_paperwork_records/")
@login_required
def paperwork_records():
    view_paperwork = PaperworkSubmission.query.all()
    form = RegisterForm()
    return render_template('view_paperwork_submission_records.html',view_paperwork=view_paperwork,form=form)


@app.route("/submit_event_report/", methods=['GET', 'POST'])
@login_required
def submiteventreport():
    form = RegisterForm()
    allowed_formats = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']

    if request.method == 'POST':
        file = request.files['file']
        selected_clubs = form.clubs.data
        event_title = request.form.get('event_title')
        event_date_paperwork = request.form.get('event_date_paperwork')
        selected_officers = form.officers.data
        remarks = request.form.get('remarks')

      
        new_eventreportsubmission = ReportSubmission(
            filename=file.filename,
            upload_proposal=file.read(),
            event_title=event_title,
            club_name=selected_clubs,
            officer_name=selected_officers,
            remarks=remarks,
            event_date_paperwork=event_date_paperwork)

        if file.mimetype in allowed_formats:
            pass
        else:
            flash("Invalid File format! Only PDF and DOCX files are allowed!")
            return redirect(url_for('submiteventreport'))

        db.session.add(new_eventreportsubmission)
        db.session.commit()
        flash(f"Event Report submission for is successful.")
        return redirect(url_for('submiteventreport'))

    return render_template('/submiteventreport.html', form=form)


@app.route("/download_report/<reportsubmission_id>")
@login_required
def downloadreport(reportsubmission_id):
    upload = ReportSubmission.query.filter_by(id=reportsubmission_id).first()
    file_data = BytesIO(upload.upload_proposal)

    if not upload:
        flash("No file detected")
        return redirect(url_for("paperwork_records"))
    
    file_extension = os.path.splitext(upload.upload_proposal)[1]
    mimetype = mimetypes.types_map.get(file_extension, 'application/octet-stream')

    return send_file(file_data, mimetype=mimetype, download_name=upload.filename, as_attachment=True)

@app.route("/view_event_report_submission_records/")
@login_required
def eventreport_records():
    view_paperwork = ReportSubmission.query.all()
    form = RegisterForm()
    return render_template('event_report_submission.html',view_paperwork=view_paperwork,form=form)


@app.route("/lecturer_space/<int:page>")
@login_required
def lecturer_space(page=1):
    per_page = 1 
    view_feedback = ContactStudent.query.filter_by(email_to=current_user.email).paginate(page=page, per_page=per_page)
    result = db.session.query(PaperworkSubmission.club_name, func.count(PaperworkSubmission.filename)).group_by(PaperworkSubmission.club_name).all()
    data = [{'Club Name': row[0], 'Count': row[1]} for row in result]

    result2 = db.session.query(ReportSubmission.club_name, func.count(ReportSubmission.filename)).group_by(ReportSubmission.club_name).all()
    data2 = [{'Club Name': row[0], 'Count': row[1]} for row in result2]

    if current_user.is_admin:
        return render_template('lecturer.html', data=data, data2=data2,view_feedback=view_feedback)
    else:
        flash('Unauthorised access detected!')
        return redirect(url_for('dashboard',page=1))
    


@app.route("/member_registeration/",methods=('GET','POST'))
def memberregistration_page(): 
    form = RegisterForm()

    if request.method == 'POST':
        selected_clubs = form.clubs.data
        studentID = request.form.get('studentID')
        firstname = request.form.get('firstname')
        email = request.form.get('email')
        phonenumber = request.form.get('phonenumber')
        password = request.form.get('password')
        acc_verify = request.form.get('acc_verify')
        is_admin = request.form.get('is_admin')
        staffID = request.form.get('staffID')
        
        new_student = User(
            staffID=staffID,
            studentID=studentID,
            firstname=firstname,
            email=email,
            phonenumber=phonenumber,
            password=password,
            acc_verify=acc_verify,
            is_admin=is_admin,
            clubs_registered=selected_clubs)
        
        if User.query.filter_by(studentID=studentID).first():
            flash("Registration Unsuccessful! Student ID already exists!","Danger")
            return redirect(url_for('memberregistration_page'))
        
        if User.query.filter_by(email=email).first():
            flash("Registration Unsuccessful! Email address already exists!","Danger")
            return redirect(url_for('memberregistration_page'))
        
        db.session.add(new_student)
        db.session.commit()
        flash("Member Registration is successful. Your account will be reviewed by the Admin soon")
        return redirect(url_for('memberpage'))
    
    return render_template('/member_registration.html', form=form)


@app.route("/update_member/<id>",methods=['GET','POST'])
@login_required
def memberupdate(id):
    form=RegisterForm()
    updates = User.query.get_or_404(id)

    if form.new_password.data:
        updates.password = generate_password_hash(form.new_password.data)

    if request.method == 'POST':
        updates.firstname = form.firstname.data
        updates.email = form.email.data
        updates.phonenumber = form.phonenumber.data 
        db.session.add(updates)
        db.session.commit()
        flash("Member details successfuly edited!")
    
    form.firstname.data = updates.firstname
    form.email.data = updates.email
    form.phonenumber.data = updates.phonenumber
    
    return render_template('update_biodata.html',form=form,updates=updates,id=updates.id)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('logged_in', None)
    flash("You have been logged out!", "info")
    return redirect(url_for('homelayout'))


with app.app_context():    
    db.create_all()
    
if __name__ == '__main__':
    app.run(debug=False)

