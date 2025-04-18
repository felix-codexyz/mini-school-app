import React, { useState } from 'react';
import axios from 'axios';

const RegistrationForm = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    program: '',
  });
  const [response, setResponse] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const backendUrl = 'https://backend.classof25.online/api/register'; // Update to your EB URL

  const programs = [
    { value: '', label: 'Select a program' },
    { value: 'computer-science', label: 'Computer Science' },
    { value: 'engineering', label: 'Engineering' },
    { value: 'business', label: 'Business' },
    { value: 'arts', label: 'Arts' },
    { value: 'medicine', label: 'Medicine' },
  ];

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setResponse(null);
    setLoading(true);

    try {
      const res = await axios.post(backendUrl, {
        name: formData.name,
        email: formData.email,
        phone: formData.phone, // Add phone
        program: formData.program, // Add program
      });
      setResponse(res.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="name" className="block text-sm font-medium text-gray-700">
            Name
          </label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={handleChange}
            required
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            placeholder="Enter your name"
          />
        </div>

        <div>
          <label htmlFor="email" className="block text-sm font-medium text-gray-700">
            Email
          </label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            required
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            placeholder="Enter your email"
          />
        </div>

        <div>
          <label htmlFor="phone" className="block text-sm font-medium text-gray-700">
            Phone Number
          </label>
          <input
            type="tel"
            id="phone"
            name="phone"
            value={formData.phone}
            onChange={handleChange}
            required
            pattern="[0-9]{10}"
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            placeholder="Enter your phone number (10 digits)"
          />
        </div>

        <div>
          <label htmlFor="program" className="block text-sm font-medium text-gray-700">
            Program of Interest
          </label>
          <select
            id="program"
            name="program"
            value={formData.program}
            onChange={handleChange}
            required
            className="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          >
            {programs.map((program) => (
              <option key={program.value} value={program.value}>
                {program.label}
              </option>
            ))}
          </select>
        </div>

        <button
          type="submit"
          disabled={loading}
          className={`w-full py-2 px-4 bg-indigo-600 text-white font-semibold rounded-md shadow-sm hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${
            loading ? 'opacity-50 cursor-not-allowed' : ''
          }`}
        >
          {loading ? 'Registering...' : 'Register'}
        </button>
      </form>

      {response && (
        <div className="p-4 bg-green-100 border border-green-400 text-green-700 rounded-md">
          <h2 className="text-lg font-semibold">Registration Successful!</h2>
          <p><strong>ID:</strong> {response.id}</p>
          <p><strong>Name:</strong> {response.name}</p>
          <p><strong>Email:</strong> {response.email}</p>
          <p><strong>Phone:</strong> {response.phone}</p>
          <p><strong>Program:</strong> {response.program}</p>
        </div>
      )}

      {error && (
        <div className="p-4 bg-red-100 border border-red-400 text-red-700 rounded-md">
          <p><strong>Error:</strong> {error}</p>
        </div>
      )}
    </div>
  );
};

export default RegistrationForm;