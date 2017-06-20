class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :confirmable, :lockable, :timeoutable, :omniauthable

  def self.from_omniauth(auth)
    email = auth.info.email
    user = where(email: email).first
    unless user
      user = User.create!(email: email, password: SecureRandom.base64(128)[0..127])
      user.confirm
    end
    user
  end
end
