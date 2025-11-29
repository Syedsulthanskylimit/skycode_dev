from rest_framework import serializers
from .models import SlaConfig

class SlaSerializer(serializers.ModelSerializer):
    class Meta:
        model = SlaConfig
        fields = '__all__'
