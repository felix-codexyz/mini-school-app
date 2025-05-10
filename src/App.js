import React from 'react';
import RegistrationForm from './components/RegistrationForm';

function App() {
  return (
    <div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
      <div className="bg-white p-8 rounded-lg shadow-lg max-w-md w-full">
        <h1 className="text-2xl font-bold text-center mb-6 text-gray-800">
          School Application Form
        </h1>
        <RegistrationForm />
      </div>
    </div>
  );
}

export default App;