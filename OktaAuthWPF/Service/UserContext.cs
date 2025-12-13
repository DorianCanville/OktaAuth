using OktaAuthWPF.Service.Object;
using System.ComponentModel;

namespace OktaAuthWPF.Service
{
    public class UserContext : INotifyPropertyChanged
    {
        private CurrentUserInfo? _currentUser;

        public CurrentUserInfo? CurrentUser
        {
            get => _currentUser;
            private set
            {
                _currentUser = value;
                OnPropertyChanged(nameof(CurrentUser));
                OnPropertyChanged(nameof(IsAuthenticated));
            }
        }

        public bool IsAuthenticated => CurrentUser != null;

        public void SetUser(CurrentUserInfo user)
        {
            CurrentUser = user;
        }

        public void Clear()
        {
            CurrentUser = null;
        }

        public event PropertyChangedEventHandler? PropertyChanged;

        private void OnPropertyChanged(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}