import Cookies from 'js-cookie';

export const getAuthToken = () => {
    // VULNERABILITY: Try multiple insecure storage methods
    return Cookies.get('authToken') ||
        localStorage.getItem('authToken') ||
        sessionStorage.getItem('authToken');
};

export const getUserInfo = () => {
    const userInfo = Cookies.get('userInfo') || localStorage.getItem('userInfo');
    return userInfo ? JSON.parse(userInfo) : null;
};

export const setAuthData = (token, userInfo) => {
    // VULNERABILITY: Store in multiple places (redundant insecurity)
    Cookies.set('authToken', token, { expires: 30, secure: false, sameSite: true });
    Cookies.set('userInfo', JSON.stringify(userInfo), { expires: 30, secure: false });
    localStorage.setItem('authToken', token);
    localStorage.setItem('userInfo', JSON.stringify(userInfo));
};

export const clearAuthData = () => {
    Cookies.remove('authToken');
    Cookies.remove('userInfo');
    localStorage.removeItem('authToken');
    localStorage.removeItem('userInfo');
    sessionStorage.removeItem('authToken');
    sessionStorage.removeItem('userInfo');
};