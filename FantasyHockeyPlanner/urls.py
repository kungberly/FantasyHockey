from django.conf.urls import url
from FantasyHockeyPlanner import views
#from .views import FantasyHockeyPlannerView
from django.contrib.auth.views import login

urlpatterns = [
    url(r'^$',views.index,name='index'),
    url(r'^login',views.login,name='login'),
    url(r'^setlineup',views.setlineup,name='setlineup'),
    url(r'^callback', views.loggedin,name='loggedin'),
    url(r'^about',views.about,name='about')
]