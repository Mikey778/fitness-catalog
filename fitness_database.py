from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class MuscleGroup(Base):
    __tablename__ = 'muscle_group'

    id = Column(Integer, primary_key=True)
    muscle_group_name = Column(String(250), nullable=False)

    @property
    def serialize(self):
        """ Return JSON Object """
        output =    {
                        'muscle_group_name': self.muscle_group_name,
                        'id': self.id,
                    }
        return output


class Exercise(Base):
    __tablename__ = 'exercises'

    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    instructions = Column(Text)
    video_link = Column(String(250))

    muscle_group_id = Column(Integer, ForeignKey('muscle_group.id'))
    muscle_group = relationship(MuscleGroup)

    @property
    def serialize(self):
        """ Return JSON Object """
        return {
            'name': self.name,
            'instructions': self.instructions,
            'id': self.id,
            'video_link': self.video_link,
        }

# default
engine = create_engine('postgresql://pguser:Gr4d3rP4$$!@localhost/fitness');

Base.metadata.create_all(engine)
